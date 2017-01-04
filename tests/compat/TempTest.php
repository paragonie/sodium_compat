<?php

class CryptoBoxSealTest extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        if (!extension_loaded('libsodium')) {
            $this->markTestSkipped('Libsodium is not installed; skipping the compatibility test suite.');
        }
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * This is currently the breaking test case.
     */
    public function testSealIsolation()
    {
        $message = str_repeat('a', 97);
        $alice_box_kp = ParagonIE_Sodium_Core_Util::hex2bin(
            '15b36cb00213373fb3fb03958fb0cc0012ecaca112fd249d3cf0961e311caac9' .
            'fb4cb34f74a928b79123333c1e63d991060244cda98affee14c3398c6d315574'
        );
        $alice_box_publickey = ParagonIE_Sodium_Core_Util::hex2bin(
            'fb4cb34f74a928b79123333c1e63d991060244cda98affee14c3398c6d315574'
        );

        $sealed_to_alice1 = \Sodium\crypto_box_seal(
            $message,
            $alice_box_publickey
        );
        $sealed_to_alice2 = ParagonIE_Sodium_Compat::crypto_box_seal(
            $message,
            $alice_box_publickey
        );

        $this->assertSame(
            strlen($sealed_to_alice1),
            strlen($sealed_to_alice2),
            'String length should not differ'
        );

        $alice_opened1 = ParagonIE_Sodium_Compat::crypto_box_seal_open($sealed_to_alice1, $alice_box_kp);
        $this->assertSame(
            bin2hex(\Sodium\crypto_box_seal_open($sealed_to_alice1, $alice_box_kp)),
            bin2hex($message),
            'Decryption failed #1: ' . $message
        );
        $this->assertSame(
            bin2hex($alice_opened1),
            bin2hex(\Sodium\crypto_box_seal_open($sealed_to_alice1, $alice_box_kp)),
            'Decryption failed #1: ' . $message
        );
        $this->assertSame(
            bin2hex($message),
            bin2hex($alice_opened1),
            'Decryption failed #1: ' . $message
        );

        $alice_opened2 = ParagonIE_Sodium_Compat::crypto_box_seal_open(
            $sealed_to_alice2,
            $alice_box_kp
        );

        $this->assertSame(
            $message,
            $alice_opened2,
            'Decryption failed #2: ' . $message
        );
        $this->assertSame(
            bin2hex(\Sodium\crypto_box_seal_open($sealed_to_alice2, $alice_box_kp)),
            bin2hex($message),
            'Decryption failed #2: ' . $message
        );
        $this->assertSame(
            bin2hex(\Sodium\crypto_box_seal_open($sealed_to_alice2, $alice_box_kp)),
            bin2hex($alice_opened2),
            'Decryption failed #2: ' . $message
        );
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_box()
     * @covers ParagonIE_Sodium_Compat::crypto_box_open()
     */
    public function testCryptoBox()
    {
        $nonce = str_repeat("\x00", 24);
        $message = str_repeat('a', 97);

        $alice_box_kp = \Sodium\crypto_box_keypair();
        $alice_box_secretkey = \Sodium\crypto_box_secretkey($alice_box_kp);
        $alice_box_publickey = \Sodium\crypto_box_publickey($alice_box_kp);

        $bob_box_kp = \Sodium\crypto_box_keypair();
        $bob_box_secretkey = \Sodium\crypto_box_secretkey($bob_box_kp);
        $bob_box_publickey = \Sodium\crypto_box_publickey($bob_box_kp);

        $alice_to_bob = \Sodium\crypto_box_keypair_from_secretkey_and_publickey(
            $alice_box_secretkey,
            $bob_box_publickey
        );
        $bob_to_alice = \Sodium\crypto_box_keypair_from_secretkey_and_publickey(
            $bob_box_secretkey,
            $alice_box_publickey
        );
        $bob_to_alice2 = ParagonIE_Sodium_Crypto::box_keypair_from_secretkey_and_publickey(
            $bob_box_secretkey,
            $alice_box_publickey
        );
        $this->assertSame($bob_to_alice, $bob_to_alice2);

        $this->assertSame(
            bin2hex(\Sodium\crypto_box($message, $nonce, $alice_to_bob)),
            bin2hex(ParagonIE_Sodium_Compat::crypto_box($message, $nonce, $alice_to_bob)),
            'box'
        );
        $this->assertSame(
            $message,
            ParagonIE_Sodium_Compat::crypto_box_open(
                \Sodium\crypto_box($message, $nonce, $alice_to_bob),
                $nonce,
                $bob_to_alice
            )
        );
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_secretbox()
     */
    public function testCryptoSecretBox()
    {
        $key = str_repeat("\x80", 32);
        $nonce = str_repeat("\x00", 24);
        $message = str_repeat('a', 97);

        $this->assertSame(
            substr(
                bin2hex(\Sodium\crypto_secretbox($message, $nonce, $key)),
                0, 32
            ),
            substr(
                bin2hex(ParagonIE_Sodium_Crypto::secretbox($message, $nonce, $key)),
                0, 32
            ),
            'secretbox - short messages'
        );
        $this->assertSame(
            $message,
            ParagonIE_Sodium_Crypto::secretbox_open(
                \Sodium\crypto_secretbox($message, $nonce, $key),
                $nonce,
                $key
            )
        );
        $this->assertSame(
            $message,
            \Sodium\crypto_secretbox_open(
                ParagonIE_Sodium_Crypto::secretbox($message, $nonce, $key),
                $nonce,
                $key
            )
        );
    }
}
