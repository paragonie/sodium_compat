<?php
use PHPUnit\Framework\TestCase;

class CompatTest extends TestCase
{
    /**
     * @before
     */
    public function before(): void
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    public function testIncrement(): void
    {
        $string = "\x00\x00\x00\x00\x00\x00\x00\x00";

        ParagonIE_Sodium_Compat::increment($string);
        $this->assertSame("0100000000000000", ParagonIE_Sodium_Core_Util::bin2hex($string));

        ParagonIE_Sodium_Compat::increment($string);
        $this->assertSame("0200000000000000", ParagonIE_Sodium_Core_Util::bin2hex($string));

        $string = "\xff\xff\x01\x20";
        ParagonIE_Sodium_Compat::increment($string);
        $this->assertSame("00000220", ParagonIE_Sodium_Core_Util::bin2hex($string));
    }

    public function testRuntimeSpeed(): void
    {
        if (ParagonIE_Sodium_Compat::polyfill_is_fast()) {
            $this->markTestSkipped('Polyfill is fast, no need to test this.');
        }
        $this->assertTrue(ParagonIE_Sodium_Compat::runtime_speed_test(100, 10));
    }

    /**
     * @throws SodiumException
     * @throws Exception
     */
    public function testKeyExchange(): void
    {
        $alice = ParagonIE_Sodium_Compat::crypto_kx_keypair();
        $alice_pk = ParagonIE_Sodium_Compat::crypto_kx_publickey($alice);
        $bob = ParagonIE_Sodium_Compat::crypto_kx_keypair();
        $bob_pk = ParagonIE_Sodium_Compat::crypto_kx_publickey($bob);

        $alice_to_bob = ParagonIE_Sodium_Compat::crypto_kx_client_session_keys($alice, $bob_pk);
        $bob_to_alice = sodium_crypto_kx_server_session_keys($bob, $alice_pk);

        $this->assertEquals($alice_to_bob[0], $bob_to_alice[1]);
        $this->assertEquals($alice_to_bob[1], $bob_to_alice[0]);
    }

    /**
     * @throws SodiumException
     */
    public function testSodiumPad(): void
    {
        for ($i = 0; $i < 100; ++$i) {
            $block = random_int(16, 256);
            $original = str_repeat("A", random_int(1, 1024));

            $padded = ParagonIE_Sodium_Compat::pad($original, $block);
            $unpadded = ParagonIE_Sodium_Compat::unpad($padded, $block);
            $this->assertEquals($unpadded, $original);

            $original = random_bytes(random_int(1, 1024));
            $padded = ParagonIE_Sodium_Compat::pad($original, $block);
            $unpadded = ParagonIE_Sodium_Compat::unpad($padded, $block);
            $this->assertEquals($unpadded, $original);
        }
    }

    /**
     * @throws SodiumException
     */
    public function testEd25519Keypairs(): void
    {
        $keypair = ParagonIE_Sodium_Core_Util::hex2bin(
            '73eda3c0594270f19fbed39440c15453c647987b5fd3a38164c383adfa638ebe' .
            '4bdae2767f0fc67ac0edbe3dff6b820a55e1769c740e8b9c72066828fc57434e' .
            '4bdae2767f0fc67ac0edbe3dff6b820a55e1769c740e8b9c72066828fc57434e'
        );
        $sk = ParagonIE_Sodium_Compat::crypto_sign_secretkey($keypair);
        $pk = ParagonIE_Sodium_Compat::crypto_sign_publickey($keypair);
        $this->assertSame(
            $keypair,
            ParagonIE_Sodium_Compat::crypto_sign_keypair_from_secretkey_and_publickey($sk, $pk)
        );
        try {
            ParagonIE_Sodium_Compat::crypto_sign_keypair_from_secretkey_and_publickey($pk, $sk);
            $this->fail('Order swapped should throw; it did not');
        } catch (SodiumException $ex) {
            $this->assertEquals(
                'secretkey should be SODIUM_CRYPTO_SIGN_SECRETKEYBYTES bytes',
                $ex->getMessage()
            );
        }
        try {
            ParagonIE_Sodium_Compat::crypto_sign_keypair_from_secretkey_and_publickey($sk, $sk);
            $this->fail('Invalid input accepted for public key');
        } catch (SodiumException $ex) {
            $this->assertEquals(
                'publickey should be SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES bytes',
                $ex->getMessage()
            );
        }
    }
    /**
     * @covers ParagonIE_Sodium_Compat::base642bin()
     * @covers ParagonIE_Sodium_Compat::bin2base64()
     * @throws TypeError
     * @throws Exception
     */
    public function testBase64(): void
    {
        for ($i = 0; $i < 100; $i++) {
            $bin = $i === 0 ? '' : random_bytes($i);
            $b64 = base64_encode($bin);
            $b64_ = ParagonIE_Sodium_Compat::bin2base64($bin, SODIUM_BASE64_VARIANT_ORIGINAL);
            $this->assertEquals($b64, $b64_);
            $bin_ = ParagonIE_Sodium_Compat::base642bin($b64, SODIUM_BASE64_VARIANT_ORIGINAL);
            $this->assertEquals($bin, $bin_);

            $b64np = ParagonIE_Sodium_Compat::bin2base64($bin, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
            $this->assertEquals(rtrim($b64, '='), $b64np);
            $binnp = ParagonIE_Sodium_Compat::base642bin($b64np, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
            $this->assertEquals($bin, $binnp);

            $b64u = strtr(base64_encode($bin), '+/', '-_');
            $b64u_ = ParagonIE_Sodium_Compat::bin2base64($bin, SODIUM_BASE64_VARIANT_URLSAFE);
            $this->assertEquals($b64u, $b64u_);
            $binu_ = ParagonIE_Sodium_Compat::base642bin($b64u, SODIUM_BASE64_VARIANT_URLSAFE);
            $this->assertEquals($bin, $binu_);

            $b64np = ParagonIE_Sodium_Compat::bin2base64($bin, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
            $this->assertEquals(rtrim($b64u, '='), $b64np);
            $binnp = ParagonIE_Sodium_Compat::base642bin($b64np, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
            $this->assertEquals($bin, $binnp);
        }

        $random = random_bytes(100);
        $x = chunk_split(base64_encode($random));
        $got = ParagonIE_Sodium_Compat::base642bin($x, SODIUM_BASE64_VARIANT_ORIGINAL, "\r\n");
        $this->assertSame($random, $got);

        // Test with an empty ignore string
        try {
            ParagonIE_Sodium_Compat::base642bin($x, SODIUM_BASE64_VARIANT_ORIGINAL, '');
            $this->fail('Should have thrown an exception for invalid base64 characters.');
        } catch (SodiumException $ex) {
            // Expected
        }

        $x = random_bytes(11);
        $x64p = ParagonIE_Sodium_Compat::bin2base64($x, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        try {
            ParagonIE_Sodium_Compat::base642bin($x64p, SODIUM_BASE64_VARIANT_ORIGINAL);
            $this->fail('Should have thrown an exception for invalid base64 characters.');
        } catch (SodiumException $ex) {
            // Expected
        }

        $x64p = ParagonIE_Sodium_Compat::bin2base64($x, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
        try {
            ParagonIE_Sodium_Compat::base642bin($x64p, SODIUM_BASE64_VARIANT_URLSAFE);
            $this->fail('Should have thrown an exception for invalid base64 characters.');
        } catch (SodiumException $ex) {
            // Expected
        }
    }

    /**
     * @covers ParagonIE_Sodium_Compat::compare()
     * @covers ParagonIE_Sodium_Compat::memcmp()
     */
    public function testCompareAndMemcmp(): void
    {
        $a = 'abcdef';
        $b = 'abcdef';
        $c = 'abcdeg';
        $d = 'abcdefg';
        $e = 'abcde';

        $this->assertSame(0, ParagonIE_Sodium_Compat::memcmp($a, $b));
        $this->assertNotSame(0, ParagonIE_Sodium_Compat::memcmp($a, $c));
        $this->assertNotSame(0, ParagonIE_Sodium_Compat::memcmp($a, $d));
        $this->assertNotSame(0, ParagonIE_Sodium_Compat::memcmp($a, $e));

        $this->assertSame(0, ParagonIE_Sodium_Compat::compare($a, $b));
        $this->assertSame(-1, ParagonIE_Sodium_Compat::compare($a, $c));
        $this->assertSame(1, ParagonIE_Sodium_Compat::compare($c, $a));
        $this->assertSame(-1, ParagonIE_Sodium_Compat::compare($a, $d));
        $this->assertSame(1, ParagonIE_Sodium_Compat::compare($d, $a));
    }

    /**
     * @covers ParagonIE_Sodium_Compat::base642bin()
     * @covers ParagonIE_Sodium_Compat::bin2base64()
     * @throws SodiumException
     */
    public function testBase64Variants(): void
    {
        $bin = 'This is a test.';
        $orig = 'VGhpcyBpcyBhIHRlc3Qu';
        $origPad = 'VGhpcyBpcyBhIHRlc3Qu';
        $url = 'VGhpcyBpcyBhIHRlc3Qu';
        $urlPad = 'VGhpcyBpcyBhIHRlc3Qu';

        $this->assertSame(
            $orig,
            ParagonIE_Sodium_Compat::bin2base64($bin, ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL_NO_PADDING)
        );
        $this->assertSame(
            $origPad,
            ParagonIE_Sodium_Compat::bin2base64($bin, ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL)
        );
        $this->assertSame(
            $url,
            ParagonIE_Sodium_Compat::bin2base64($bin, ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE_NO_PADDING)
        );
        $this->assertSame(
            $urlPad,
            ParagonIE_Sodium_Compat::bin2base64($bin, ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE)
        );

        $this->assertSame(
            $bin,
            ParagonIE_Sodium_Compat::base642bin($orig, ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL_NO_PADDING)
        );
        $this->assertSame(
            $bin,
            ParagonIE_Sodium_Compat::base642bin($origPad, ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL)
        );
        $this->assertSame(
            $bin,
            ParagonIE_Sodium_Compat::base642bin($url, ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE_NO_PADDING)
        );
        $this->assertSame(
            $bin,
            ParagonIE_Sodium_Compat::base642bin($urlPad, ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE)
        );

        try {
            ParagonIE_Sodium_Compat::base642bin('a', -1);
            $this->fail('invalid variant');
        } catch (SodiumException $ex) {
        }
        try {
            ParagonIE_Sodium_Compat::bin2base64('a', -1);
            $this->fail('invalid variant');
        } catch (SodiumException $ex) {
        }

        $this->assertSame(
            '',
            ParagonIE_Sodium_Compat::base642bin('', ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL)
        );
        $this->assertSame(
            '',
            ParagonIE_Sodium_Compat::bin2base64('', ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL)
        );

        $b64 = ParagonIE_Sodium_Compat::bin2base64($bin, SODIUM_BASE64_VARIANT_ORIGINAL);
        $this->assertSame(
            $bin,
            ParagonIE_Sodium_Compat::base642bin($b64, SODIUM_BASE64_VARIANT_ORIGINAL, ' ')
        );

        try {
            ParagonIE_Sodium_Compat::base642bin('!@#$%', ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL);
            $this->fail('invalid base64');
        } catch (SodiumException $ex) {
            // Expected
        }
    }
}
