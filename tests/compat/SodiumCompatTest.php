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
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
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
     *
     */
    public function testAeadChapoly()
    {
        $message = str_repeat("\x00", 128);
        $key = str_repeat("\x00", 32);
        $nonce = str_repeat("\x00", 8);
        $ad = '';

        $pecl = \Sodium\crypto_aead_chacha20poly1305_encrypt($message, $ad, $nonce, $key);
        $compat = ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_encrypt($message, $ad, $nonce, $key);
        $this->assertSame(bin2hex($pecl), bin2hex($compat), 'Empty test');

        $this->assertSame(
            $message,
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_decrypt($pecl, $ad, $nonce, $key),
            'Blank Message decryption'
        );

        $message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        $pecl = \Sodium\crypto_aead_chacha20poly1305_encrypt($message, $ad, $nonce, $key);
        $compat = ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_encrypt($message, $ad, $nonce, $key);
        $this->assertSame(bin2hex($pecl), bin2hex($compat), 'Static test');
        $this->assertSame(
            $message,
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_decrypt($pecl, $ad, $nonce, $key),
            'Static Message decryption'
        );

        $ad = 'test';
        $pecl = \Sodium\crypto_aead_chacha20poly1305_encrypt($message, $ad, $nonce, $key);
        $compat = ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_encrypt($message, $ad, $nonce, $key);
        $this->assertSame(bin2hex($pecl), bin2hex($compat), 'Static test with AD');
        $this->assertSame(
            $message,
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_decrypt($pecl, $ad, $nonce, $key),
            'Static Message decryption (with AD)'
        );

        $key = random_bytes(32);
        $nonce = random_bytes(8);
        $ad = '';

        $pecl = \Sodium\crypto_aead_chacha20poly1305_encrypt($message, $ad, $nonce, $key);
        $compat = ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_encrypt($message, $ad, $nonce, $key);
        $this->assertSame(bin2hex($pecl), bin2hex($compat), 'Random test');
        $this->assertSame(
            $message,
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_decrypt($pecl, $ad, $nonce, $key),
            'Random Message decryption'
        );

        $ad = 'test';
        $pecl = \Sodium\crypto_aead_chacha20poly1305_encrypt($message, $ad, $nonce, $key);
        $compat = ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_encrypt($message, $ad, $nonce, $key);
        $this->assertSame(bin2hex($pecl), bin2hex($compat), 'Random test with AD');
        $this->assertSame(
            $message,
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_decrypt($pecl, $ad, $nonce, $key),
            'Random Message decryption (with AD)'
        );
    }

    /**
     *
     */
    public function testAeadChapolyIetf()
    {
        $message = str_repeat("\x00", 128);
        $key = str_repeat("\x00", 32);
        $nonce = str_repeat("\x00", 12);
        $ad = '';

        $pecl = \Sodium\crypto_aead_chacha20poly1305_ietf_encrypt($message, $ad, $nonce, $key);
        $compat = ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_encrypt($message, $ad, $nonce, $key);
        $this->assertSame(bin2hex($pecl), bin2hex($compat), 'Empty test');

        $this->assertSame(
            $message,
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt($pecl, $ad, $nonce, $key),
            'Blank Message decryption'
        );

        $message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        $pecl = \Sodium\crypto_aead_chacha20poly1305_ietf_encrypt($message, $ad, $nonce, $key);
        $compat = ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_encrypt($message, $ad, $nonce, $key);
        $this->assertSame(bin2hex($pecl), bin2hex($compat), 'Static test');
        $this->assertSame(
            $message,
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt($pecl, $ad, $nonce, $key),
            'Static Message decryption'
        );

        $ad = 'test';
        $pecl = \Sodium\crypto_aead_chacha20poly1305_ietf_encrypt($message, $ad, $nonce, $key);
        $compat = ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_encrypt($message, $ad, $nonce, $key);
        $this->assertSame(bin2hex($pecl), bin2hex($compat), 'Static test with AD');
        $this->assertSame(
            $message,
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt($pecl, $ad, $nonce, $key),
            'Static Message decryption (with AD)'
        );

        $key = random_bytes(32);
        $nonce = random_bytes(12);
        $ad = '';

        $pecl = \Sodium\crypto_aead_chacha20poly1305_ietf_encrypt($message, $ad, $nonce, $key);
        $compat = ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_encrypt($message, $ad, $nonce, $key);
        $this->assertSame(bin2hex($pecl), bin2hex($compat), 'Random test');
        $this->assertSame(
            $message,
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt($pecl, $ad, $nonce, $key),
            'Random Message decryption'
        );

        $ad = 'test';
        $pecl = \Sodium\crypto_aead_chacha20poly1305_ietf_encrypt($message, $ad, $nonce, $key);
        $compat = ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_encrypt($message, $ad, $nonce, $key);
        $this->assertSame(bin2hex($pecl), bin2hex($compat), 'Random test with AD');
        $this->assertSame(
            $message,
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt($pecl, $ad, $nonce, $key),
            'Random Message decryption (with AD)'
        );
    }

    /**
     *
     */
    public function testCryptoAuth()
    {
        $message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        $key = random_bytes(32);

        $this->assertSame(
            bin2hex(\Sodium\crypto_auth($message, $key)),
            bin2hex(ParagonIE_Sodium_Compat::crypto_auth($message, $key))
        );
        $mac = \Sodium\crypto_auth($message, $key);
        $this->assertTrue(
            ParagonIE_Sodium_Compat::crypto_auth_verify($mac, $message, $key)
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
        $bob_to_alice2 = ParagonIE_Sodium_Compat::crypto_box_keypair_from_secretkey_and_publickey(
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

        $message = str_repeat("Lorem ipsum dolor sit amet, consectetur adipiscing elit. ", 8);
        $this->assertSame(
            bin2hex(\Sodium\crypto_box($message, $nonce, $alice_to_bob)),
            bin2hex(ParagonIE_Sodium_Compat::crypto_box($message, $nonce, $alice_to_bob)),
            'crypto_box is failing with large messages'
        );
        $this->assertSame(
            bin2hex($message),
            bin2hex(
                ParagonIE_Sodium_Compat::crypto_box_open(
                    \Sodium\crypto_box($message, $nonce, $alice_to_bob),
                    $nonce,
                    $bob_to_alice
                )
            )
        );
    }

    public function testCryptoBoxSeal()
    {
        $msg = ParagonIE_Sodium_Core_Util::hex2bin(
            '7375f4094f1151640bd853cb13dbc1a0ee9e13b0287a89d34fa2f6732be9de13f88457553d'.
            '768347116522d6d32c9cb353ef07aa7c83bd129b2bb5db35b28334c935b24f2639405a0604'
        );
        $kp = ParagonIE_Sodium_Core_Util::hex2bin(
            '36a6c2b96a650d80bf7e025e0f58f3d636339575defb370801a54213bd54582d'.
            '5aecbcf7866e7a4d58a6c1317e2b955f54ecbe2fcbbf7d262c10636ed524480c'
        );
        $alice_opened2 = ParagonIE_Sodium_Compat::crypto_box_seal_open($msg, $kp);
        $this->assertSame(
            bin2hex('This is for your eyes only'),
            bin2hex($alice_opened2),
            'Decryption failed #2'
        );
        $alice_box_kp = ParagonIE_Sodium_Core_Util::hex2bin(
            '15b36cb00213373fb3fb03958fb0cc0012ecaca112fd249d3cf0961e311caac9' .
            'fb4cb34f74a928b79123333c1e63d991060244cda98affee14c3398c6d315574'
        );
        $alice_box_publickey = ParagonIE_Sodium_Core_Util::hex2bin(
            'fb4cb34f74a928b79123333c1e63d991060244cda98affee14c3398c6d315574'
        );
        $anonymous_message_to_alice = \Sodium\crypto_box_seal(
            'Anonymous message',
            $alice_box_publickey);
        $decrypted_message = ParagonIE_Sodium_Compat::crypto_box_seal_open(
            $anonymous_message_to_alice,
            $alice_box_kp
        );
        $this->assertSame(
            'Anonymous message',
            $decrypted_message
        );

        $messages = array(
            'test',
            'slightly longer message',
            str_repeat('a', 29) . ' 32',
            str_repeat('a', 30) . ' 33',
            str_repeat('a', 31) . ' 34',
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
        );
        foreach ($messages as $message) {
            $sealed_to_alice1 = \Sodium\crypto_box_seal($message, $alice_box_publickey);
            $sealed_to_alice2 = ParagonIE_Sodium_Compat::crypto_box_seal(
                $message,
                $alice_box_publickey
            );

            $this->assertSame(
                ParagonIE_Sodium_Core_Util::strlen($sealed_to_alice1),
                ParagonIE_Sodium_Core_Util::strlen($sealed_to_alice2),
                'String length should not differ'
            );

            $alice_opened1 = ParagonIE_Sodium_Compat::crypto_box_seal_open($sealed_to_alice1, $alice_box_kp);
            $this->assertSame(
                bin2hex(\Sodium\crypto_box_seal_open($sealed_to_alice1, $alice_box_kp)),
                bin2hex($message),
                'Decryption failed #1: ' . $message
            );
            $this->assertSame(
                bin2hex($message),
                bin2hex($alice_opened1),
                'Decryption failed #1: ' . $message
            );
            $this->assertSame(
                bin2hex($alice_opened1),
                bin2hex(\Sodium\crypto_box_seal_open($sealed_to_alice1, $alice_box_kp)),
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
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_generichash()
     */
    public function testCryptoGenerichash()
    {
        $this->assertSame(
            bin2hex(\Sodium\crypto_generichash('apple')),
            bin2hex(ParagonIE_Sodium_Compat::crypto_generichash('apple')),
            'BLAKE2b implementation'
        );

        $this->assertSame(
            bin2hex(\Sodium\crypto_generichash('apple', 'catastrophic failure')),
            bin2hex(ParagonIE_Sodium_Compat::crypto_generichash('apple', 'catastrophic failure')),
            'BLAKE2b with a key'
        );

        $this->assertSame(
            bin2hex(\Sodium\crypto_generichash('apple', '', 64)),
            bin2hex(ParagonIE_Sodium_Compat::crypto_generichash('apple', '', 64)),
            'BLAKE2b implementation with output length'
        );

        $this->assertSame(
            bin2hex(\Sodium\crypto_generichash('apple', '', 17)),
            bin2hex(ParagonIE_Sodium_Compat::crypto_generichash('apple', '', 17)),
            'BLAKE2b implementation with output length'
        );

        $this->assertSame(
            bin2hex(\Sodium\crypto_generichash('apple', 'catastrophic failure', 24)),
            bin2hex(ParagonIE_Sodium_Compat::crypto_generichash('apple', 'catastrophic failure', 24)),
            'BLAKE2b implementation with output length'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_generichash_init()
     * @covers ParagonIE_Sodium_Compat::crypto_generichash_update()
     * @covers ParagonIE_Sodium_Compat::crypto_generichash_final()
     */
    public function testCryptoGenerichashStream()
    {
        $key =  "\x1c" . str_repeat("\x80", 30) . "\xaf";
        $ctx = \Sodium\crypto_generichash_init($key);
        $this->assertSame(
            bin2hex($ctx),
            bin2hex(ParagonIE_Sodium_Compat::crypto_generichash_init($key)),
            'BLAKE2b Context Serialization'
        );

        $subCtx = ParagonIE_Sodium_Core_BLAKE2b::stringToContext($ctx);
        $this->assertSame(
            bin2hex($ctx),
            bin2hex(ParagonIE_Sodium_Core_BLAKE2b::contextToString($subCtx)),
            'Context serialization / deserialization'
        );
        $this->assertEquals(
            $subCtx,
            ParagonIE_Sodium_Core_BLAKE2b::stringToContext(
                ParagonIE_Sodium_Core_BLAKE2b::contextToString($subCtx)
            ),
            'Determinism'
        );

        $nativeCtx = '';
        for ($i = 0; $i < ParagonIE_Sodium_Core_Util::strlen($ctx); ++$i) {
            $nativeCtx .= $ctx[$i];
        }

        \Sodium\crypto_generichash_update($nativeCtx, 'Paragon Initiative');
        ParagonIE_Sodium_Compat::crypto_generichash_update($ctx, 'Paragon Initiative');

        $this->assertSame(
            bin2hex($nativeCtx),
            bin2hex($ctx),
            'generichash_update() 1'
        );
        \Sodium\crypto_generichash_update($nativeCtx, ' Enterprises, LLC');
        ParagonIE_Sodium_Compat::crypto_generichash_update($ctx, ' Enterprises, LLC');

        $this->assertSame(
            bin2hex($nativeCtx),
            bin2hex($ctx),
            'generichash_update() 2'
        );

        $randoms = array(
            random_bytes(127),
            random_bytes(1),
            random_bytes(128),
            random_bytes(random_int(1, 127)),
            random_bytes(random_int(1, 127)),
            random_bytes(random_int(1 << 9, 1 << 15)),
            random_bytes(random_int(1 << 9, 1 << 15)),
            random_bytes(random_int(1, 127)),
            random_bytes(random_int(1 << 9, 1 << 15))
        );
        $n = 2;
        foreach ($randoms as $random) {
            \Sodium\crypto_generichash_update($nativeCtx, $random);
            ParagonIE_Sodium_Compat::crypto_generichash_update($ctx, $random);
            $this->assertSame(
                bin2hex($nativeCtx),
                bin2hex($ctx),
                'generichash_update() ' . (++$n)
            );
        }

        $this->assertSame(
            bin2hex(\Sodium\crypto_generichash_final($nativeCtx, 32)),
            bin2hex(ParagonIE_Sodium_Compat::crypto_generichash_final($ctx, 32)),
            'generichash_final()'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_sign_seed_keypair()
     */
    public function testSignKeypair()
    {
        $seed = random_bytes(32);
        $kp = \Sodium\crypto_sign_seed_keypair($seed);
        $this->assertSame(
            bin2hex($kp),
            bin2hex(
                ParagonIE_Sodium_Compat::crypto_sign_seed_keypair($seed)
            ),
            'crypto_sign_seed_keypair() is invalid.'
        );
        $secret = \Sodium\crypto_sign_secretkey($kp);
        $public = \Sodium\crypto_sign_publickey($kp);

        $pk = '';
        $sk = '';
        ParagonIE_Sodium_Core_Ed25519::seed_keypair($pk, $sk, $seed);
        $this->assertSame(
            bin2hex($secret),
            bin2hex($sk),
            'Seed secret key'
        );
        $this->assertSame(
            bin2hex($public),
            bin2hex($pk),
            'Seed public key'
        );
        $keypair = ParagonIE_Sodium_Compat::crypto_sign_keypair();
        $secret = \Sodium\crypto_sign_secretkey($keypair);
        $public = \Sodium\crypto_sign_publickey($keypair);

        $this->assertSame(
            bin2hex($public),
            bin2hex(
                \Sodium\crypto_sign_publickey_from_secretkey($secret)
            ),
            'Conversion from existing secret key is failing. This is a very bad thing!'
        );

        $this->assertSame(
            bin2hex(\Sodium\crypto_sign_ed25519_sk_to_curve25519($secret)),
            bin2hex(ParagonIE_Sodium_Compat::crypto_sign_ed25519_sk_to_curve25519($secret)),
            'crypto_sign_ed25519_sk_to_curve25519'
        );
    }

    public function testSignKeypair2()
    {
        $keypair = \Sodium\crypto_sign_keypair();
        $secret = \Sodium\crypto_sign_secretkey($keypair);
        $public = \Sodium\crypto_sign_publickey($keypair);

        $this->assertSame(
            bin2hex($public),
            bin2hex(
                ParagonIE_Sodium_Compat::crypto_sign_publickey_from_secretkey($secret)
            ),
            'Conversion from existing secret key is failing. This is a very bad thing!'
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
        $keypair = ParagonIE_Sodium_Core_Util::hex2bin(
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
            bin2hex(ParagonIE_Sodium_Compat::crypto_sign_detached($message, $secret)),
            'Generated different signatures'
        );

        $this->assertSame(
            $expected,
            bin2hex(ParagonIE_Sodium_Compat::crypto_sign_detached($message, $secret)),
            'Generated different signatures'
        );

        $message = 'Test message: ' . base64_encode(random_bytes(33));
        $keypair = \Sodium\crypto_sign_keypair();
        $secret = \Sodium\crypto_sign_secretkey($keypair);
        $public = \Sodium\crypto_sign_publickey($keypair);
        $public2 = ParagonIE_Sodium_Compat::crypto_sign_publickey($keypair);
        $this->assertSame($public, $public2);

        $signature = \Sodium\crypto_sign_detached($message, $secret);
        $this->assertSame(
            bin2hex($signature),
            bin2hex(ParagonIE_Sodium_Compat::crypto_sign_detached($message, $secret)),
            'Generated different signatures'
        );
        $this->assertTrue(
            ParagonIE_Sodium_Compat::crypto_sign_verify_detached($signature, $message, $public),
            'Signature verification failed in compatibility test.'
        );

        // Signed messages (NaCl compatibility):
        $signed = \Sodium\crypto_sign($message, $secret);
        $this->assertSame(
            bin2hex($signed),
            bin2hex(ParagonIE_Sodium_Compat::crypto_sign($message, $secret)),
            'Basic crypto_sign works'
        );

        $this->assertSame(
            bin2hex(\Sodium\crypto_sign_open($signed, $public)),
            bin2hex(ParagonIE_Sodium_Compat::crypto_sign_open($signed, $public)),
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
        $message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";

        $this->assertSame(
            ParagonIE_Sodium_Core_Util::substr(
                bin2hex(\Sodium\crypto_secretbox($message, $nonce, $key)),
                0, 32
            ),
            ParagonIE_Sodium_Core_Util::substr(
                bin2hex(ParagonIE_Sodium_Compat::crypto_secretbox($message, $nonce, $key)),
                0, 32
            ),
            'secretbox - short messages'
        );
        $this->assertSame(
            $message,
            ParagonIE_Sodium_Compat::crypto_secretbox_open(
                \Sodium\crypto_secretbox($message, $nonce, $key),
                $nonce,
                $key
            )
        );
        $this->assertSame(
            $message,
            \Sodium\crypto_secretbox_open(
                ParagonIE_Sodium_Compat::crypto_secretbox($message, $nonce, $key),
                $nonce,
                $key
            )
        );
        $message = str_repeat('a', 97);
        $this->assertSame(
            bin2hex(\Sodium\crypto_secretbox($message, $nonce, $key)),
            bin2hex(ParagonIE_Sodium_Compat::crypto_secretbox($message, $nonce, $key)),
            'secretbox - long messages (multiple of 16)'
        );

        $message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";

        $message = str_repeat($message, 16);

        $this->assertSame(
            bin2hex(\Sodium\crypto_secretbox($message, $nonce, $key)),
            bin2hex(ParagonIE_Sodium_Compat::crypto_secretbox($message, $nonce, $key)),
            'secretbox - long messages (multiple of 16)'
        );

        $message .= 'a';

        $this->assertSame(
            bin2hex(\Sodium\crypto_secretbox($message, $nonce, $key)),
            bin2hex(ParagonIE_Sodium_Compat::crypto_secretbox($message, $nonce, $key)),
            'secretbox - long messages (NOT a multiple of 16)'
        );

        $message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";

        $this->assertSame(
            bin2hex(\Sodium\crypto_secretbox($message, $nonce, $key)),
            bin2hex(ParagonIE_Sodium_Compat::crypto_secretbox($message, $nonce, $key)),
            'secretbox - medium messages'
        );

        $message = str_repeat(random_bytes(8), (1 << 15) - 64) . random_bytes(64);
        $this->assertSame(
            bin2hex(\Sodium\crypto_secretbox($message, $nonce, $key)),
            bin2hex(ParagonIE_Sodium_Compat::crypto_secretbox($message, $nonce, $key)),
            'secretbox - medium messages'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_scalarmult_base()
     */
    public function testCryptoScalarmultBase()
    {
        $keypair = \Sodium\crypto_box_keypair();
        $secret = \Sodium\crypto_box_secretkey($keypair);
        $public = \Sodium\crypto_box_publickey($keypair);

        $this->assertSame(
            $public,
            ParagonIE_Sodium_Compat::crypto_scalarmult_base($secret)
        );
    }
    /**
     * @covers ParagonIE_Sodium_Compat::crypto_scalarmult()
     */
    public function testCryptoScalarmult()
    {
        $alice_box_kp = \Sodium\crypto_box_keypair();
        $alice_box_secretkey = \Sodium\crypto_box_secretkey($alice_box_kp);
        $alice_box_publickey = \Sodium\crypto_box_publickey($alice_box_kp);

        $bob_box_kp = \Sodium\crypto_box_keypair();
        $bob_box_secretkey = \Sodium\crypto_box_secretkey($bob_box_kp);
        $bob_box_publickey = \Sodium\crypto_box_publickey($bob_box_kp);

        $this->assertSame(
            \Sodium\crypto_scalarmult($alice_box_secretkey, $bob_box_publickey),
            ParagonIE_Sodium_Compat::crypto_scalarmult($alice_box_secretkey, $bob_box_publickey)
        );

        $this->assertSame(
            \Sodium\crypto_scalarmult($bob_box_secretkey, $alice_box_publickey),
            ParagonIE_Sodium_Compat::crypto_scalarmult($bob_box_secretkey, $alice_box_publickey)
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

        $streamed = \Sodium\crypto_stream(1024, $nonce, $key);
        $this->assertSame(
            bin2hex($streamed),
            bin2hex(ParagonIE_Sodium_Compat::crypto_stream(1024, $nonce, $key)),
            'crypto_stream() is not working'
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

        $message = 'Test message: ' . base64_encode(random_bytes(93));

        $streamed = \Sodium\crypto_stream_xor($message, $nonce, $key);
        $this->assertSame(
            bin2hex($streamed),
            bin2hex(ParagonIE_Sodium_Compat::crypto_stream_xor($message, $nonce, $key)),
            'crypto_stream_xor() is not working'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_kx()
     */
    public function testCryptoKx()
    {
        $alice_box_kp = \Sodium\crypto_box_keypair();
        $alice_box_secretkey = \Sodium\crypto_box_secretkey($alice_box_kp);
        $alice_box_publickey = \Sodium\crypto_box_publickey($alice_box_kp);

        $bob_box_kp = \Sodium\crypto_box_keypair();
        $bob_box_publickey = \Sodium\crypto_box_publickey($bob_box_kp);

        // Let's designate Bob as the server.

        $this->assertSame(
            bin2hex(
                \Sodium\crypto_kx(
                    $alice_box_secretkey, $bob_box_publickey,
                    $alice_box_publickey, $bob_box_publickey
                )
            ),
            bin2hex(
                ParagonIE_Sodium_Compat::crypto_kx(
                    $alice_box_secretkey, $bob_box_publickey,
                    $alice_box_publickey, $bob_box_publickey
                )
            )
        );
    }

    /**
     *
     */
    public function testCryptoShorthash()
    {
        $message = str_repeat("\x00", 8);
        $key = str_repeat("\x00", 16);
        $this->shorthashVerify($message, $key);

        $key = str_repeat("\xff", 16);
        $this->shorthashVerify($message, $key);

        $message = str_repeat("\x01", 8);
        $this->shorthashVerify($message, $key);

        $message = str_repeat("\x01", 7) . "\x02";
        $this->shorthashVerify($message, $key);

        $key = str_repeat("\xff", 8) . str_repeat("\x00", 8);
        $this->shorthashVerify($message, $key);

        $message = str_repeat("\x00", 8);
        $key = random_bytes(16);

        $this->shorthashVerify($message, $key);

        $message = random_bytes(random_int(1, 100));
        $this->shorthashVerify($message, $key);
    }
    
    protected function shorthashVerify($m, $k)
    {
        $this->assertSame(
            bin2hex(\Sodium\crypto_shorthash($m, $k)),
            bin2hex(ParagonIE_Sodium_Compat::crypto_shorthash($m, $k))
        );
    }
}
