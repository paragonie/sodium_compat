<?php

/**
 * Class SodiumCompatTest
 */
class SodiumCompatTest extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        if (!extension_loaded('libsodium')) {
            $this->markTestSkipped('Libsodium is not installed; skipping the compatibility test suite.');
        }
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = false;
    }

    /**
     * @covers ParagonIE_Sodium_Core_Util::compare()
     */
    public function testCompare()
    {
        $a = pack('H*', '589a84d7ec2db8f982841cedca674ec1');
        $b = $a;
        $b[15] = 'a';
        $this->assertSame(
            \Sodium\compare($a, $b),
            ParagonIE_Sodium_Core_Util::compare($a, $b),
            bin2hex($a) . ' vs ' . bin2hex($b)
        );

        $a = random_bytes(16);
        $b = $a;
        $b[15] = 'a';

        $this->assertSame(
            \Sodium\compare($a, $b),
            ParagonIE_Sodium_Core_Util::compare($a, $b),
            bin2hex($a)
        );
    }

    /**
     * @covers ParagonIE_Sodium_Core_Util::bin2hex()
     */
    public function testBin2hex()
    {
        $str = random_bytes(random_int(1, 63));
        $this->assertSame(
            \Sodium\bin2hex($str),
            ParagonIE_Sodium_Core_Util::bin2hex($str)
        );
    }

    /**
     * @covers ParagonIE_Sodium_Core_Util::hex2bin()
     */
    public function testHex2bin()
    {
        $str = bin2hex(random_bytes(random_int(1, 63)));
        $this->assertSame(
            \Sodium\hex2bin($str),
            ParagonIE_Sodium_Core_Util::hex2bin($str)
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
     * @covers ParagonIE_Sodium_Compat::crypto_sign()
     * @covers ParagonIE_Sodium_Compat::crypto_sign_open()
     * @covers ParagonIE_Sodium_Compat::crypto_sign_detached()
     * @covers ParagonIE_Sodium_Compat::crypto_sign_verify_detached()
     */
    public function testCryptoSign()
    {
        $keypair = hex2bin(
            'fcdf31aae72e280cc760186d83e41be216fe1f2c7407dd393ad3a45a2fa501a4' .
            'ee00f800ae9e986b994ec0af67fe6b017eb78704e81639eee7efa3d3a831d1bc' .
            'ee00f800ae9e986b994ec0af67fe6b017eb78704e81639eee7efa3d3a831d1bc'
        );
        $secret = \Sodium\crypto_sign_secretkey($keypair);
        $public = \Sodium\crypto_sign_publickey($keypair);

        $this->assertSame(
            $secret,
            ParagonIE_Sodium_Compat::crypto_sign_secretkey($keypair),
            'crypto_sign_secretkey() is broken'
        );
        $this->assertSame(
            $public,
            ParagonIE_Sodium_Compat::crypto_sign_publickey($keypair),
            'crypto_sign_publickey() is broken'
        );

        $message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        $expected =
        '36a6d2748f6ab8f76c122a562d55343cb7c6f15c8a45bd55bd8b9e9fadd2363f' .
        '370cb78fba42c550d487b9bd7413312b6490c8b3ee2cea638997172a9c8c250f';

        $this->assertSame(
            $expected,
            bin2hex(\Sodium\crypto_sign_detached($message, $secret)),
            'Generated different signatures'
        );

        $this->assertSame(
            bin2hex(\Sodium\crypto_sign_detached($message, $secret)),
            bin2hex(ParagonIE_Sodium_Crypto::sign_detached($message, $secret)),
            'Generated different signatures'
        );  

        $this->assertSame(
            $expected,
            bin2hex(ParagonIE_Sodium_Crypto::sign_detached($message, $secret)),
            'Generated different signatures'
        );

        $message = 'Test message: ' . base64_encode(random_bytes(33));

        $signature = \Sodium\crypto_sign_detached($message, $secret);
        $this->assertSame(
            bin2hex($signature),
            bin2hex(ParagonIE_Sodium_Crypto::sign_detached($message, $secret)),
            'Generated different signatures'
        );
        $this->assertTrue(
            ParagonIE_Sodium_Crypto::sign_verify_detached($signature, $message, $public),
            'Signature verification failed in compatibility test.'
        );

        // Signed messages (NaCl compatibility):
        $signed = \Sodium\crypto_sign($message, $secret);
        $this->assertSame(
            bin2hex($signed),
            bin2hex(ParagonIE_Sodium_Crypto::sign($message, $secret)),
            'Basic crypto_sign works'
        );

        $this->assertSame(
            bin2hex(\Sodium\crypto_sign_open($signed, $public)),
            bin2hex(ParagonIE_Sodium_Crypto::sign_open($signed, $public)),
            'Basic crypto_sign_open works'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_secretbox()
     */
    public function testCryptoSecretBox()
    {
        $key = str_repeat("\x80", 32);
        $nonce = str_repeat("\x00", 24);
        $message = "a";

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

        $message = str_repeat($message, 16);

        $this->assertSame(
            bin2hex(\Sodium\crypto_secretbox($message, $nonce, $key)),
            bin2hex(ParagonIE_Sodium_Crypto::secretbox($message, $nonce, $key)),
            'secretbox - long messages (multiple of 16)'
        );

        $message .= 'a';

        $this->assertSame(
            bin2hex(\Sodium\crypto_secretbox($message, $nonce, $key)),
            bin2hex(ParagonIE_Sodium_Crypto::secretbox($message, $nonce, $key)),
            'secretbox - long messages (NOT a multiple of 16)'
        );

        $message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";

        $this->assertSame(
            bin2hex(\Sodium\crypto_secretbox($message, $nonce, $key)),
            bin2hex(ParagonIE_Sodium_Crypto::secretbox($message, $nonce, $key)),
            'secretbox - medium messages'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_box_secretkey()
     * @covers ParagonIE_Sodium_Compat::crypto_box_publickey()
     */
    public function testCryptoBoxKeypairs()
    {
        $keypair = \Sodium\crypto_box_keypair();
        $secret = \Sodium\crypto_box_secretkey($keypair);
        $public = \Sodium\crypto_box_publickey($keypair);

        $this->assertSame(
            $secret,
            ParagonIE_Sodium_Compat::crypto_box_secretkey($keypair)
        );
        $this->assertSame(
            $public,
            ParagonIE_Sodium_Compat::crypto_box_publickey($keypair)
        );
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_stream()
     */
    public function testCryptoStream()
    {
        $key = str_repeat("\x80", 32);
        $nonce = str_repeat("\x00", 24);

        $streamed = \Sodium\crypto_stream(64, $nonce, $key);
        $this->assertSame(
            bin2hex($streamed),
            bin2hex(ParagonIE_Sodium_Compat::crypto_stream(64, $nonce, $key)),
            'crypto_stream_xor() is not working'
        );
        $key = random_bytes(32);
        $nonce = random_bytes(24);

        $streamed = \Sodium\crypto_stream(64, $nonce, $key);
        $this->assertSame(
            bin2hex($streamed),
            bin2hex(ParagonIE_Sodium_Compat::crypto_stream(64, $nonce, $key)),
            'crypto_stream_xor() is not working'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_stream_xor()
     */
    public function testCryptoStreamXor()
    {
        $key = str_repeat("\x80", 32);
        $nonce = str_repeat("\x00", 24);
        $message = 'Test message';

        $streamed = \Sodium\crypto_stream_xor($message, $nonce, $key);
        $this->assertSame(
            bin2hex($streamed),
            bin2hex(ParagonIE_Sodium_Compat::crypto_stream_xor($message, $nonce, $key)),
            'crypto_stream_xor() is not working'
        );

        $key = random_bytes(32);
        $nonce = random_bytes(24);

        $message = 'Test message: ' . base64_encode(random_bytes(33));

        $streamed = \Sodium\crypto_stream_xor($message, $nonce, $key);
        $this->assertSame(
            bin2hex($streamed),
            bin2hex(ParagonIE_Sodium_Compat::crypto_stream_xor($message, $nonce, $key)),
            'crypto_stream_xor() is not working'
        );
    }
}
