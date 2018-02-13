<?php

/**
 * Class ExceptionTest
 *
 * This tests failure conditions.
 */
class ExceptionTest extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_encrypt()
     * @covers ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_encrypt()
     * @covers ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_decrypt()
     * @covers ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt()
     * @throws SodiumException
     * @throws TypeError
     */
    public function testCryptoAeadChapoly()
    {
        $key = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES);
        $message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        $aad = random_bytes(64);
        $nonce = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES);
        $ietfNonce = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES);

        $cipher1 = ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_encrypt(
            $message,
            $aad,
            $nonce,
            $key
        );
        $cipher2 = ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_encrypt(
            $message,
            $aad,
            $ietfNonce,
            $key
        );

        try {
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_encrypt(
                array(),
                $aad,
                $nonce,
                $key
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }

        try {
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_encrypt(
                $message,
                array(),
                $nonce,
                $key
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }

        try {
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_encrypt(
                $message,
                $aad,
                array(),
                $key
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }

        try {
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_encrypt(
                $message,
                $aad,
                $nonce,
                array()
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }
        try {
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_encrypt(
                $message,
                $aad,
                $ietfNonce,
                $key
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        }
        try {
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_encrypt(
                $message,
                $aad,
                $nonce,
                $key
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        }

        // DECRYPT:

        try {
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_decrypt(
                array(),
                $aad,
                $nonce,
                $key
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }

        try {
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_decrypt(
                $cipher1,
                array(),
                $nonce,
                $key
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }

        try {
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_decrypt(
                $cipher1,
                $aad,
                array(),
                $key
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }

        try {
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_decrypt(
                $cipher1,
                $aad,
                $nonce,
                array()
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }
        try {
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_decrypt(
                $cipher1,
                $aad,
                $ietfNonce,
                $key
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        }
        try {
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_decrypt(
                $cipher2,
                $aad,
                $nonce,
                $key
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        }
        try {
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt(
                $cipher1,
                $aad,
                $nonce,
                $key
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        }
        try {
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt(
                $cipher1,
                $aad,
                $ietfNonce,
                $key
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        }
    }


    /**
     * @covers ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_encrypt()
     * @covers ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_decrypt()
     * @throws SodiumException
     * @throws TypeError
     */
    public function testCryptoAeadXChapolyIetf()
    {
        $key = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);
        $message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        $aad = random_bytes(64);
        $nonce = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);

        $cipher1 = ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_encrypt(
            $message,
            $aad,
            $nonce,
            $key
        );

        try {
            ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_encrypt(
                array(),
                $aad,
                $nonce,
                $key
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }

        try {
            ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_encrypt(
                $message,
                array(),
                $nonce,
                $key
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }

        try {
            ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_encrypt(
                $message,
                $aad,
                array(),
                $key
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }

        try {
            ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_encrypt(
                $message,
                $aad,
                $nonce,
                array()
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }

        // DECRYPT:

        try {
            ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_decrypt(
                array(),
                $aad,
                $nonce,
                $key
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }

        try {
            ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_decrypt(
                $cipher1,
                array(),
                $nonce,
                $key
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }

        try {
            ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_decrypt(
                $cipher1,
                $aad,
                array(),
                $key
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }

        try {
            ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_decrypt(
                $cipher1,
                $aad,
                $nonce,
                array()
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }
        try {
            ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_decrypt(
                $cipher1,
                $aad,
                ParagonIE_Sodium_Core_Util::substr($nonce, 0, 8),
                $key
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        }
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_auth()
     */
    public function testCryptoAuth()
    {
        $key = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_AUTH_KEYBYTES);
        $message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        $message .= random_bytes(64);
        try {
            ParagonIE_Sodium_Compat::crypto_auth(array(), $key);
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }

        try {
            ParagonIE_Sodium_Compat::crypto_auth($message, array());
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }
        try {
            ParagonIE_Sodium_Compat::crypto_auth($key, $message);
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        }
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_auth_verify()
     */
    public function testCryptoAuthVerify()
    {
        $key = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_AUTH_KEYBYTES);
        $message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        $message .= random_bytes(64);
        $mac = ParagonIE_Sodium_Compat::crypto_auth($message, $key);
        try {
            ParagonIE_Sodium_Compat::crypto_auth_verify(array(), $message, $key);
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }
        try {
            ParagonIE_Sodium_Compat::crypto_auth_verify($mac, array(), $key);
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }
        try {
            ParagonIE_Sodium_Compat::crypto_auth_verify($mac, $message, array());
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }

        try {
            ParagonIE_Sodium_Compat::crypto_auth_verify($mac, $key, $message);
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        }

        try {
            ParagonIE_Sodium_Compat::crypto_auth_verify($message, $mac, $key);
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        }
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_box()
     * @covers ParagonIE_Sodium_Compat::crypto_box_open()
     * @throws SodiumException
     * @throws TypeError
     */
    public function testCryptoBox()
    {
        $nonce = str_repeat("\x00", 24);
        $message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        $message .= str_repeat("\x20", 64);

        $zero_key = str_repeat("\x00", 32);
        $alice_secret = ParagonIE_Sodium_Core_Util::hex2bin('69f208412d8dd5db9d0c6d18512e86f0ec75665ab841372d57b042b27ef89d8c');
        $bob_secret = ParagonIE_Sodium_Core_Util::hex2bin('b581fb5ae182a16f603f39270d4e3b95bc008310b727a11dd4e784a0044d461b');
        $bob_public = ParagonIE_Sodium_Core_Util::hex2bin('e8980c86e032f1eb2975052e8d65bddd15c3b59641174ec9678a53789d92c754');

        $alice_to_bob = ParagonIE_Sodium_Crypto::box_keypair_from_secretkey_and_publickey(
            $alice_secret,
            $bob_public
        );

        $alice_to_zero = ParagonIE_Sodium_Crypto::box_keypair_from_secretkey_and_publickey(
            $alice_secret,
            $zero_key
        );
        $bob_to_zero = ParagonIE_Sodium_Crypto::box_keypair_from_secretkey_and_publickey(
            $bob_secret,
            $zero_key
        );

        try {
            ParagonIE_Sodium_Compat::crypto_box($message, $nonce, $alice_to_zero);
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        }

        try {
            ParagonIE_Sodium_Compat::crypto_box($message, $nonce, $bob_to_zero);
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        }
        $ciphertext = ParagonIE_Sodium_Compat::crypto_box($message, $nonce, $alice_to_bob);

        try {
            ParagonIE_Sodium_Compat::crypto_box_open(array(), $nonce, $alice_to_bob);
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }

        try {
            ParagonIE_Sodium_Compat::crypto_box_open($ciphertext, array(), $alice_to_bob);
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }

        try {
            ParagonIE_Sodium_Compat::crypto_box_open($ciphertext, $nonce, array());
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_secretbox()
     * @covers ParagonIE_Sodium_Compat::crypto_secretbox_open()
     * @throws SodiumException
     * @throws TypeError
     */
    public function testCryptoSecretbox()
    {
        $message = str_repeat("\x00", 128);
        $nonce = str_repeat("\x00", 24);
        $key = str_repeat("\x00", 32);

        try {
            ParagonIE_Sodium_Compat::crypto_secretbox(
                array(),
                $nonce,
                $key
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof SodiumException || $ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof SodiumException || $ex instanceof TypeError);
        }

        try {
            ParagonIE_Sodium_Compat::crypto_secretbox(
                $message,
                array(),
                $key
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof SodiumException || $ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof SodiumException || $ex instanceof TypeError);
        }
        try {
            ParagonIE_Sodium_Compat::crypto_secretbox(
                $message,
                $nonce,
                array()
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof SodiumException || $ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof SodiumException || $ex instanceof TypeError);
        }

        // Now we test decryption
        $ciphertext = ParagonIE_Sodium_Compat::crypto_secretbox(
            $message,
            $nonce,
            $key
        );
        try {
            ParagonIE_Sodium_Compat::crypto_secretbox_open(
                '',
                $nonce,
                $key
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        }
        try {
            ParagonIE_Sodium_Compat::crypto_secretbox_open(
                array(),
                $nonce,
                $key
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }
        try {
            ParagonIE_Sodium_Compat::crypto_secretbox_open(
                $ciphertext,
                array(),
                $key
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }
        try {
            ParagonIE_Sodium_Compat::crypto_secretbox_open(
                $ciphertext,
                $nonce,
                array()
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }
        try {
            ParagonIE_Sodium_Compat::crypto_secretbox_open(
                ParagonIE_Sodium_Core_Util::substr($ciphertext, 1),
                $nonce,
                $key
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof SodiumException);
        }
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_sign_verify_detached()
     * @throws SodiumException
     * @throws TypeError
     */
    public function testCryptoSignVerifyDetached()
    {
        $secretKey = str_repeat("\x00", 64);
        $publicKey = ParagonIE_Sodium_Compat::crypto_sign_publickey_from_secretkey($secretKey);
        $message = str_repeat("\x00", 128);
        $signature = ParagonIE_Sodium_Compat::crypto_sign_detached($message, $secretKey);
        try {
            ParagonIE_Sodium_Compat::crypto_sign_verify_detached(
                array(),
                $message,
                $publicKey
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }
        try {
            ParagonIE_Sodium_Compat::crypto_sign_verify_detached(
                $signature,
                array(),
                $publicKey
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }
        try {
            ParagonIE_Sodium_Compat::crypto_sign_verify_detached(
                $signature,
                $message,
                array()
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Throwable $ex) {
            $this->assertTrue($ex instanceof TypeError);
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof TypeError);
        }
        try {
            // Zero byte signature
            ParagonIE_Sodium_Compat::crypto_sign_verify_detached(
                str_repeat("\x00", 64),
                $message,
                $publicKey
            );
            $this->fail('Silent failure occurred instead of exception being thrown');
        } catch (Exception $ex) {
            $this->assertTrue($ex instanceof Exception);
        }
    }
}
