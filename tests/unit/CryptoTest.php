<?php

class CryptoTest extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_auth()
     * @covers ParagonIE_Sodium_Compat::crypto_auth_verify()
     */
    public function testCryptoAuth()
    {
        $key = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_AUTH_KEYBYTES);
        $message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        $message .= random_bytes(64);

        $mac = ParagonIE_Sodium_Compat::crypto_auth($message, $key);
        $this->assertTrue(
            ParagonIE_Sodium_Compat::crypto_auth_verify($mac, $message, $key)
        );
        $message .= 'wrong';
        $this->assertFalse(
            ParagonIE_Sodium_Compat::crypto_auth_verify($mac, $message, $key)
        );
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_decrypt()
     * @covers ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_encrypt()
     */
    public function testChapoly()
    {
        $message = str_repeat("\x00", 128);
        $key = str_repeat("\x00", 32);
        $nonce = str_repeat("\x00", 8);
        $ad = '';

        $this->assertSame(
            $message,
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_decrypt(
                ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_encrypt(
                    $message,
                    $ad,
                    $nonce,
                    $key
                ),
                $ad,
                $nonce,
                $key
            ),
            'Blank Message decryption'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_box()
     * @covers ParagonIE_Sodium_Compat::crypto_box_open()
     */
    public function testCryptoBox()
    {
        $nonce = str_repeat("\x00", 24);
        $message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        $message .= str_repeat("\x20", 64);

        $alice_secret = ParagonIE_Sodium_Core_Util::hex2bin('69f208412d8dd5db9d0c6d18512e86f0ec75665ab841372d57b042b27ef89d8c');
        $alice_public = ParagonIE_Sodium_Core_Util::hex2bin('ac3a70ba35df3c3fae427a7c72021d68f2c1e044040b75f17313c0c8b5d4241d');
        $bob_secret = ParagonIE_Sodium_Core_Util::hex2bin('b581fb5ae182a16f603f39270d4e3b95bc008310b727a11dd4e784a0044d461b');
        $bob_public = ParagonIE_Sodium_Core_Util::hex2bin('e8980c86e032f1eb2975052e8d65bddd15c3b59641174ec9678a53789d92c754');

        $alice_to_bob = ParagonIE_Sodium_Crypto::box_keypair_from_secretkey_and_publickey(
            $alice_secret,
            $bob_public
        );
        $bob_to_alice = ParagonIE_Sodium_Crypto::box_keypair_from_secretkey_and_publickey(
            $bob_secret,
            $alice_public
        );

        $this->assertSame(
            bin2hex(ParagonIE_Sodium_Crypto::box($message, $nonce, $bob_to_alice)),
            bin2hex(ParagonIE_Sodium_Crypto::box($message, $nonce, $alice_to_bob)),
            'box'
        );
    }


    /**
     * @covers ParagonIE_Sodium_Compat::crypto_box_seal()
     * @covers ParagonIE_Sodium_Compat::crypto_box_seal_open()
     */
    public function testBoxSeal()
    {
        $message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";

        $alice_box_kp = ParagonIE_Sodium_Core_Util::hex2bin(
            '15b36cb00213373fb3fb03958fb0cc0012ecaca112fd249d3cf0961e311caac9' .
            'fb4cb34f74a928b79123333c1e63d991060244cda98affee14c3398c6d315574'
        );
        $alice_box_publickey = ParagonIE_Sodium_Core_Util::hex2bin(
            'fb4cb34f74a928b79123333c1e63d991060244cda98affee14c3398c6d315574'
        );

        $sealed_to_alice = ParagonIE_Sodium_Compat::crypto_box_seal($message, $alice_box_publickey);

        $alice_opened = ParagonIE_Sodium_Compat::crypto_box_seal_open($sealed_to_alice, $alice_box_kp);
        $this->assertSame(
            $message,
            $alice_opened,
            'Decryption failed'
        );
    }

    /**
     *
     */
    public function testKeypairs()
    {
        $box_keypair = ParagonIE_Sodium_Compat::crypto_box_keypair();
        $box_public = ParagonIE_Sodium_Compat::crypto_box_publickey($box_keypair);

        $sealed = ParagonIE_Sodium_Compat::crypto_box_seal('Test message', $box_public);
        $opened = ParagonIE_Sodium_Compat::crypto_box_seal_open($sealed, $box_keypair);
        $this->assertSame(
            'Test message',
            $opened
        );
        #

        $sign_keypair = ParagonIE_Sodium_Core_Util::hex2bin(
            'fcdf31aae72e280cc760186d83e41be216fe1f2c7407dd393ad3a45a2fa501a4' .
            'ee00f800ae9e986b994ec0af67fe6b017eb78704e81639eee7efa3d3a831d1bc' .
            'ee00f800ae9e986b994ec0af67fe6b017eb78704e81639eee7efa3d3a831d1bc'
        );
        $sign_secret = ParagonIE_Sodium_Compat::crypto_sign_secretkey($sign_keypair);
        $sign_public = ParagonIE_Sodium_Compat::crypto_sign_publickey($sign_keypair);
        $this->assertSame(
            ParagonIE_Sodium_Core_Util::substr($sign_secret, 32),
            $sign_public
        );

        $sign_keypair = ParagonIE_Sodium_Compat::crypto_sign_keypair();
        $sign_secret = ParagonIE_Sodium_Compat::crypto_sign_secretkey($sign_keypair);
        $sign_public = ParagonIE_Sodium_Compat::crypto_sign_publickey($sign_keypair);
        $this->assertSame(
            ParagonIE_Sodium_Core_Util::substr($sign_secret, 32),
            $sign_public
        );

        $sig = ParagonIE_Sodium_Compat::crypto_sign_detached('Test message', $sign_secret);
        $this->assertTrue(
            ParagonIE_Sodium_Compat::crypto_sign_verify_detached($sig, 'Test message', $sign_public)
        );
    }

    /**
     * @covers ParagonIE_Sodium_Crypto::scalarmult_base()
     */
    public function testScalarmultBase()
    {
        $alice_secret = ParagonIE_Sodium_Core_Util::hex2bin('69f208412d8dd5db9d0c6d18512e86f0ec75665ab841372d57b042b27ef89d8c');
        $alice_public = ParagonIE_Sodium_Core_Util::hex2bin('ac3a70ba35df3c3fae427a7c72021d68f2c1e044040b75f17313c0c8b5d4241d');

        $this->assertSame(
            bin2hex($alice_public),
            bin2hex(ParagonIE_Sodium_Crypto::scalarmult_base($alice_secret))
        );
    }

    /**
     * @covers ParagonIE_Sodium_Crypto::scalarmult()
     */
    public function testScalarmult()
    {
        $alice_secret = ParagonIE_Sodium_Core_Util::hex2bin('69f208412d8dd5db9d0c6d18512e86f0ec75665ab841372d57b042b27ef89d8c');
        $alice_public = ParagonIE_Sodium_Core_Util::hex2bin('ac3a70ba35df3c3fae427a7c72021d68f2c1e044040b75f17313c0c8b5d4241d');
        $bob_secret = ParagonIE_Sodium_Core_Util::hex2bin('b581fb5ae182a16f603f39270d4e3b95bc008310b727a11dd4e784a0044d461b');
        $bob_public = ParagonIE_Sodium_Core_Util::hex2bin('e8980c86e032f1eb2975052e8d65bddd15c3b59641174ec9678a53789d92c754');

        $this->assertSame(
            bin2hex(ParagonIE_Sodium_Crypto::scalarmult($alice_secret, $bob_public)),
            bin2hex(ParagonIE_Sodium_Crypto::scalarmult($bob_secret, $alice_public))
        );
    }

    /**
     * @covers ParagonIE_Sodium_Crypto::sign_detached()
     */
    public function testSignDetached()
    {
        $secret = ParagonIE_Sodium_Core_Util::hex2bin(
            'fcdf31aae72e280cc760186d83e41be216fe1f2c7407dd393ad3a45a2fa501a4' .
            'ee00f800ae9e986b994ec0af67fe6b017eb78704e81639eee7efa3d3a831d1bc'
        );
        $message = 'Test message';
        $this->assertSame(
            '5e413e791d9bcdbaa1cfd4f83b01c73926f436a467cfc2634fc90651fb0465bfea76083b4ff247f925df96e89da3d9edc11029adf1601cd0f97d1b2c4b02e905',
            bin2hex(ParagonIE_Sodium_Crypto::sign_detached($message, $secret)),
            'Generated different signatures'
        );

        $message = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.';
        $this->assertSame(
            '36a6d2748f6ab8f76c122a562d55343cb7c6f15c8a45bd55bd8b9e9fadd2363f370cb78fba42c550d487b9bd7413312b6490c8b3ee2cea638997172a9c8c250f',
            bin2hex(ParagonIE_Sodium_Crypto::sign_detached($message, $secret)),
            'Generated different signatures'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Crypto::sign()
     * @covers ParagonIE_Sodium_Crypto::sign_open()
     */
    public function testSign()
    {
        $secret = ParagonIE_Sodium_Core_Util::hex2bin(
            'fcdf31aae72e280cc760186d83e41be216fe1f2c7407dd393ad3a45a2fa501a4' .
            'ee00f800ae9e986b994ec0af67fe6b017eb78704e81639eee7efa3d3a831d1bc'
        );
        $public = ParagonIE_Sodium_Core_Util::hex2bin(
            'ee00f800ae9e986b994ec0af67fe6b017eb78704e81639eee7efa3d3a831d1bc'
        );
        $message = random_bytes(random_int(1, 1024));
        $signed = ParagonIE_Sodium_Compat::crypto_sign($message, $secret);
        $this->assertSame(
            bin2hex($message),
            bin2hex(ParagonIE_Sodium_Compat::crypto_sign_open($signed, $public)),
            'Signature broken with known good keys'
        );
        $sign_keypair = ParagonIE_Sodium_Compat::crypto_sign_keypair();
        $sign_secret = ParagonIE_Sodium_Compat::crypto_sign_secretkey($sign_keypair);
        $sign_public = ParagonIE_Sodium_Compat::crypto_sign_publickey($sign_keypair);

        $message = random_bytes(random_int(1, 1024));
        $signed = ParagonIE_Sodium_Compat::crypto_sign($message, $sign_secret);
        $this->assertSame(
            bin2hex($message),
            bin2hex(ParagonIE_Sodium_Compat::crypto_sign_open($signed, $sign_public)),
            'Signature broken with random keys'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_secretbox()
     * @covers ParagonIE_Sodium_Compat::crypto_secretbox_open()
     */
    public function testSecretbox()
    {
        $secret = random_bytes(32);
        $nonce = random_bytes(24);

        $message = random_bytes(random_int(1, 1024));
        $cipher = ParagonIE_Sodium_Compat::crypto_secretbox($message, $nonce, $secret);

        $this->assertSame(
            $message,
            ParagonIE_Sodium_Compat::crypto_secretbox_open($cipher, $nonce, $secret)
        );
    }

    /**
     * @covers ParagonIE_Sodium_Crypto::sign_verify_detached()
     */
    public function testVerifyDetached()
    {
        $public = ParagonIE_Sodium_Core_Util::hex2bin('ee00f800ae9e986b994ec0af67fe6b017eb78704e81639eee7efa3d3a831d1bc');

        $message = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.';
        $sig = ParagonIE_Sodium_Core_Util::hex2bin(
            '36a6d2748f6ab8f76c122a562d55343cb7c6f15c8a45bd55bd8b9e9fadd2363f' .
            '370cb78fba42c550d487b9bd7413312b6490c8b3ee2cea638997172a9c8c250f'
        );
        $this->assertTrue(
            ParagonIE_Sodium_Crypto::sign_verify_detached($sig, $message, $public),
            'Invalid signature verification checking'
        );
    }
}
