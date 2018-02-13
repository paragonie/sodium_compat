<?php

/**
 * Class PedanticTest
 *
 * These are very, very pedantic compatibility tests.
 *
 * To include this in the test suite: vendor/bin/phpunit --bootstrap=autoload-pedantic.php
 */
class PedanticTest extends PHPUnit_Framework_TestCase
{
    const DEFAULT_MAX_LENGTH = 32;

    protected $oldFastMult = false;

    public function setUp()
    {
        if (!extension_loaded('libsodium')) {
            $this->markTestSkipped('Libsodium is not installed; skipping the compatibility test suite.');
        }
        if (!defined('DO_PEDANTIC_TEST')) {
            $this->markTestSkipped('Skipping slow, pedantic test suite.');
        } else {
            if (!DO_PEDANTIC_TEST) {
                $this->markTestSkipped('Skipping slow, pedantic test suite.');
            }
        }
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;

        $this->oldFastMult = ParagonIE_Sodium_Compat::$fastMult;
        ParagonIE_Sodium_Compat::$fastMult = true;
    }

    public function tearDown()
    {
        ParagonIE_Sodium_Compat::$fastMult = $this->oldFastMult;
    }

    /**
     * @return array<int, int>
     */
    public function getInteresting32BitInts()
    {
        return array(
            0x00000000, 0x01234567,
            0x11111111, 0x12345678,
            0x22222222, 0x23456789,
            0x33333333, 0x3456789a,
            0x44444444, 0x456789ab,
            0x55555555, 0x56789abc,
            0x66666666, 0x6789abcd,
            0x77777777, 0x789abcde,
            0x7fffffff, 0x80000000, 0x80808080,
            0x88888888, 0x89abcdef,
            0x99999999, 0x9abcdef0,
            0xaaaaaaaa, 0xabcdef01,
            0xbbbbbbbb, 0xbcdef012,
            0xcccccccc, 0xcdef0123,
            0xdddddddd, 0xdef01234,
            0xeeeeeeee, 0xef012345,
            0xffffffff, 0xf0123456
        );
    }

    /**
     * @return array<int, string>
     * @throws TypeError
     */
    public function getInteresting16ByteStrings()
    {
        $strings = array();
        foreach ($this->getInteresting32BitInts() as $i => $int) {
            $tmp = ParagonIE_Sodium_Core_Util::store32_le($int);
            $strings[$i] = str_repeat($tmp, 4);
        }
        return $strings;
    }

    /**
     * @return array<int, string>
     * @throws TypeError
     */
    public function getInteresting32ByteStrings()
    {
        $strings = array();
        foreach ($this->getInteresting32BitInts() as $i => $int) {
            $tmp = ParagonIE_Sodium_Core_Util::store32_le($int);
            $strings[$i] = str_repeat($tmp, 8);
        }
        return $strings;
    }

    /**
     * @return array<int, string>
     *
     * @return array
     * @throws TypeError
     */
    public function getCryptoBoxKeys()
    {
        $keys = $this->getInteresting32ByteStrings();
        foreach ($keys as $i => $v) {
            if ($v === str_repeat("\x00", 32)) {
                // This one is explicitly not allowed, and will error.
                unset($keys[$i]);
            }
        }
        return array_values($keys);
    }

    /**
     * @param int $min
     * @param int $max
     * @return array<int, string>
     * @throws TypeError
     */
    public function getInterestingStringsVaryingLength($min = 1, $max = self::DEFAULT_MAX_LENGTH)
    {
        if ($min < 1) {
            $min = 1;
        }
        $strings = array();
        $j = 0;
        for ($l = $min; $l <= $max; ++$l) {
            foreach ($this->getInteresting32BitInts() as $i => $int) {
                $tmp = ParagonIE_Sodium_Core_Util::store32_le($int);
                $strings[$j++] = ParagonIE_Sodium_Core_Util::substr(
                    str_repeat($tmp, $l >> 4),
                    0,
                    $l
                );
            }
        }

        // Include very long strings each time.
        $l = 1 << 16;
        foreach ($this->getInteresting32BitInts() as $i => $int) {
            $tmp = ParagonIE_Sodium_Core_Util::store32_le($int);
            $strings[$j++] = ParagonIE_Sodium_Core_Util::substr(
                str_repeat($tmp, $l >> 4),
                0,
                $l
            );
        }
        return $strings;
    }


    /**
     * @covers ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_encrypt()
     * @covers ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt()
     */
    public function testCryptoAeadChapoly()
    {
        $keys = $this->getInteresting32ByteStrings();
        $plaintexts = $this->getInterestingStringsVaryingLength();
        $aads = $plaintexts;
        $aads []= '';
        $nonce = random_bytes(12);

        foreach ($plaintexts as $plaintext) {
            foreach ($aads as $aad) {
                foreach ($keys as $key) {
                    $canonical = \Sodium\crypto_aead_chacha20poly1305_ietf_encrypt($plaintext, $aad, $nonce, $key);
                    $this->assertSame(
                        bin2hex($canonical),
                        bin2hex(ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_encrypt($plaintext, $aad, $nonce, $key)),
                        'crypto_aead_chacha20poly1305_ietf_encrypt(): pedantic test case'
                    );
                    $this->assertSame(
                        bin2hex($plaintext),
                        bin2hex(ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt($canonical, $aad, $nonce, $key)),
                        'crypto_aead_chacha20poly1305_ietf_decrypt(): pedantic test case'
                    );
                }
            }
        }
        exit;
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_auth()
     */
    public function testCryptoAuth()
    {
        $keys = $this->getInteresting32ByteStrings();
        $plaintexts = $this->getInterestingStringsVaryingLength();

        foreach ($plaintexts as $plaintext) {
            foreach ($keys as $key) {
                $canonical = \Sodium\crypto_auth($plaintext, $key);
                $this->assertSame(
                    bin2hex($canonical),
                    bin2hex(ParagonIE_Sodium_Compat::crypto_auth($plaintext, $key)),
                    'crypto_auth(): pedantic test case'
                );
                $this->assertTrue(
                    ParagonIE_Sodium_Compat::crypto_auth_verify($canonical, $plaintext, $key),
                    'crypto_auth_verify(): pedantic test case'
                );
            }
        }
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_box()
     * @covers ParagonIE_Sodium_Compat::crypto_box_open()
     */
    public function testCryptoBox()
    {
        $secretKeys = $this->getCryptoBoxKeys();
        $publicKeys = array();
        $nonce = random_bytes(24);
        foreach ($secretKeys as $id => $secret) {
            try {
                $publicKeys[] = ParagonIE_Sodium_Compat::crypto_scalarmult_base($secret);
            } catch (Exception $ex) {
                unset($secretKeys[$id]);
            }
        }

        $plaintexts = $this->getInterestingStringsVaryingLength();

        foreach ($plaintexts as $plaintext) {
            $a = 0; $b = count($publicKeys) - 1;
            while ($b >= 0) {
                $keypair = ParagonIE_Sodium_Compat::crypto_box_keypair_from_secretkey_and_publickey(
                    $secretKeys[$a],
                    $publicKeys[$b]
                );
                $canonical = \Sodium\crypto_box($plaintext, $nonce, $keypair);
                $this->assertSame(
                    bin2hex($canonical),
                    bin2hex(ParagonIE_Sodium_Compat::crypto_box($plaintext, $nonce, $keypair)),
                    'crypto_box(): pedantic test case'
                );
                $this->assertSame(
                    bin2hex($plaintext),
                    bin2hex(ParagonIE_Sodium_Compat::crypto_box_open($canonical, $nonce, $keypair)),
                    'crypto_box_open(): pedantic test case'
                );
                --$b; ++$a;
            }
        }
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_generichash()
     */
    public function testGenerichash()
    {
        $keys = $this->getInteresting32ByteStrings();
        $plaintexts = $this->getInterestingStringsVaryingLength();

        foreach ($plaintexts as $plaintext) {
            $this->assertSame(
                bin2hex(\Sodium\crypto_generichash($plaintext)),
                bin2hex(ParagonIE_Sodium_Compat::crypto_generichash($plaintext)),
                'crypto_generichash(): pedantic test case'
            );
            foreach ($keys as $key) {
                $this->assertSame(
                    bin2hex(\Sodium\crypto_generichash($plaintext, $key)),
                    bin2hex(ParagonIE_Sodium_Compat::crypto_generichash($plaintext, $key)),
                    'crypto_generichash(): pedantic test case'
                );
            }
            for ($len = 16; $len < 64; ++$len) {
                $this->assertSame(
                    bin2hex(\Sodium\crypto_generichash($plaintext, null, $len)),
                    bin2hex(ParagonIE_Sodium_Compat::crypto_generichash($plaintext, null, $len)),
                    'crypto_generichash(): pedantic test case'
                );
            }
        }
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_secretbox()
     * @covers ParagonIE_Sodium_Compat::crypto_secretbox_open()
     */
    public function testCryptoSecretbox()
    {
        $keys = $this->getInteresting32ByteStrings();
        $plaintexts = $this->getInterestingStringsVaryingLength();
        $nonce = random_bytes(24);

        foreach ($plaintexts as $plaintext) {
            foreach ($keys as $key) {
                $canonical = \Sodium\crypto_secretbox($plaintext, $nonce, $key);
                $this->assertSame(
                    bin2hex($canonical),
                    bin2hex(ParagonIE_Sodium_Compat::crypto_secretbox($plaintext, $nonce, $key)),
                    'crypto_secretbox(): pedantic test case'
                );
                $this->assertSame(
                    bin2hex($plaintext),
                    bin2hex(ParagonIE_Sodium_Compat::crypto_secretbox_open($canonical, $nonce, $key)),
                    'crypto_secretbox_open(): pedantic test case'
                );
            }
        }
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_shorthash()
     */
    public function testShorthash()
    {
        $keys = $this->getInteresting16ByteStrings();
        $plaintexts = $this->getInterestingStringsVaryingLength();

        foreach ($plaintexts as $plaintext) {
            foreach ($keys as $key) {
                $this->assertSame(
                    bin2hex(\Sodium\crypto_shorthash($plaintext, $key)),
                    bin2hex(ParagonIE_Sodium_Compat::crypto_shorthash($plaintext, $key)),
                    'crypto_shorthash(): pedantic test case'
                );
            }
        }
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_sign()
     * @covers ParagonIE_Sodium_Compat::crypto_sign_open()
     * @covers ParagonIE_Sodium_Compat::crypto_sign_detached()
     * @covers ParagonIE_Sodium_Compat::crypto_sign_verify_detached()
     */
    public function testCryptoSign()
    {
        $seeds = $this->getCryptoBoxKeys();
        $secretKeys = array();
        $publicKeys = array();
        foreach ($seeds as $seed) {
            $keypair = ParagonIE_Sodium_Compat::crypto_sign_seed_keypair($seed);
            $secretKeys[] = ParagonIE_Sodium_Compat::crypto_sign_secretkey($keypair);
            $publicKeys[] = ParagonIE_Sodium_Compat::crypto_sign_publickey($keypair);
        }

        $plaintexts = $this->getInterestingStringsVaryingLength();
        foreach ($plaintexts as $plaintext) {
            for ($i = 0; $i < count($seeds); ++$i) {
                $canonical = \Sodium\crypto_sign($plaintext, $secretKeys[$i]);
                $this->assertSame(
                    bin2hex($canonical),
                    bin2hex(ParagonIE_Sodium_Compat::crypto_sign($plaintext, $secretKeys[$i])),
                    'crypto_sign(): pedantic test'
                );
                $this->assertSame(
                    bin2hex($plaintext),
                    bin2hex(ParagonIE_Sodium_Compat::crypto_sign_open($canonical, $publicKeys[$i])),
                    'crypto_sign_open(): pedantic test'
                );

                $canonical = \Sodium\crypto_sign_detached($plaintext, $secretKeys[$i]);
                $this->assertSame(
                    bin2hex($canonical),
                    bin2hex(ParagonIE_Sodium_Compat::crypto_sign_detached($plaintext, $secretKeys[$i])),
                    'crypto_sign_detached(): pedantic test'
                );
                $this->assertTrue(
                    ParagonIE_Sodium_Compat::crypto_sign_verify_detached($canonical, $plaintext, $publicKeys[$i]),
                    'crypto_sign_verify_detached(): pedantic test'
                );
            }
        }
    }
}
