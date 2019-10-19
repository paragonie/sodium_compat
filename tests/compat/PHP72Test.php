<?php

/**
 * Class SodiumCompatTest
 */
class PHP72Test extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        if (PHP_VERSION_ID < 70200) {
            $this->markTestSkipped('PHP < 7.2.0; skipping PHP 7.2 compatibility test suite.');
        }
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @throws SodiumException
     */
    public function testAdd()
    {
        $a = "\x12\x34\x56\x78";
        $b = "\x01\x00\x00\x00";
        $c = "\xFF\xFF\xFF\xFF";

        $tmp = $a;
        ParagonIE_Sodium_Compat::add($tmp, $b);
        $this->assertEquals("\x13\x34\x56\x78", $tmp);
        ParagonIE_Sodium_Compat::add($tmp, $b);
        $this->assertEquals("\x14\x34\x56\x78", $tmp);

        $tmp = $a;
        ParagonIE_Sodium_Compat::add($tmp, $c);
        $this->assertEquals("\x11\x34\x56\x78", $tmp);
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
            sodium_compare($a, $b),
            ParagonIE_Sodium_Core_Util::compare($a, $b),
            bin2hex($a) . ' vs ' . bin2hex($b)
        );

        $a = random_bytes(16);
        $b = $a;
        $b[15] = 'a';

        $this->assertSame(
            sodium_compare($a, $b),
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
            sodium_bin2hex($str),
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
            sodium_hex2bin($str),
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

        $pecl = sodium_crypto_aead_chacha20poly1305_encrypt($message, $ad, $nonce, $key);
        $compat = ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_encrypt($message, $ad, $nonce, $key);
        $this->assertSame(bin2hex($pecl), bin2hex($compat), 'Empty test');

        $this->assertSame(
            $message,
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_decrypt($pecl, $ad, $nonce, $key),
            'Blank Message decryption'
        );

        $message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        $pecl = sodium_crypto_aead_chacha20poly1305_encrypt($message, $ad, $nonce, $key);
        $compat = ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_encrypt($message, $ad, $nonce, $key);
        $this->assertSame(bin2hex($pecl), bin2hex($compat), 'Static test');
        $this->assertSame(
            $message,
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_decrypt($pecl, $ad, $nonce, $key),
            'Static Message decryption'
        );

        $ad = 'test';
        $pecl = sodium_crypto_aead_chacha20poly1305_encrypt($message, $ad, $nonce, $key);
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

        $pecl = sodium_crypto_aead_chacha20poly1305_encrypt($message, $ad, $nonce, $key);
        $compat = ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_encrypt($message, $ad, $nonce, $key);
        $this->assertSame(bin2hex($pecl), bin2hex($compat), 'Random test');
        $this->assertSame(
            $message,
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_decrypt($pecl, $ad, $nonce, $key),
            'Random Message decryption'
        );

        $ad = 'test';
        $pecl = sodium_crypto_aead_chacha20poly1305_encrypt($message, $ad, $nonce, $key);
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

        $pecl = sodium_crypto_aead_chacha20poly1305_ietf_encrypt($message, $ad, $nonce, $key);
        $compat = ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_encrypt($message, $ad, $nonce, $key);
        $this->assertSame(bin2hex($pecl), bin2hex($compat), 'Empty test');

        $this->assertSame(
            $message,
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt($pecl, $ad, $nonce, $key),
            'Blank Message decryption'
        );

        $message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        $pecl = sodium_crypto_aead_chacha20poly1305_ietf_encrypt($message, $ad, $nonce, $key);
        $compat = ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_encrypt($message, $ad, $nonce, $key);
        $this->assertSame(bin2hex($pecl), bin2hex($compat), 'Static test');
        $this->assertSame(
            $message,
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt($pecl, $ad, $nonce, $key),
            'Static Message decryption'
        );

        $ad = 'test';
        $pecl = sodium_crypto_aead_chacha20poly1305_ietf_encrypt($message, $ad, $nonce, $key);
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

        $pecl = sodium_crypto_aead_chacha20poly1305_ietf_encrypt($message, $ad, $nonce, $key);
        $compat = ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_encrypt($message, $ad, $nonce, $key);
        $this->assertSame(bin2hex($pecl), bin2hex($compat), 'Random test');
        $this->assertSame(
            $message,
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt($pecl, $ad, $nonce, $key),
            'Random Message decryption'
        );

        $ad = 'test';
        $pecl = sodium_crypto_aead_chacha20poly1305_ietf_encrypt($message, $ad, $nonce, $key);
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
            bin2hex(sodium_crypto_auth($message, $key)),
            bin2hex(ParagonIE_Sodium_Compat::crypto_auth($message, $key))
        );
        $mac = sodium_crypto_auth($message, $key);
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

        $alice_box_kp = sodium_crypto_box_keypair();
        $alice_box_secretkey = sodium_crypto_box_secretkey($alice_box_kp);
        $alice_box_publickey = sodium_crypto_box_publickey($alice_box_kp);

        $bob_box_kp = sodium_crypto_box_keypair();
        $bob_box_secretkey = sodium_crypto_box_secretkey($bob_box_kp);
        $bob_box_publickey = sodium_crypto_box_publickey($bob_box_kp);

        $alice_to_bob = sodium_crypto_box_keypair_from_secretkey_and_publickey(
            $alice_box_secretkey,
            $bob_box_publickey
        );
        $bob_to_alice = sodium_crypto_box_keypair_from_secretkey_and_publickey(
            $bob_box_secretkey,
            $alice_box_publickey
        );
        $bob_to_alice2 = ParagonIE_Sodium_Compat::crypto_box_keypair_from_secretkey_and_publickey(
            $bob_box_secretkey,
            $alice_box_publickey
        );
        $this->assertSame($bob_to_alice, $bob_to_alice2);

        $this->assertSame(
            bin2hex(sodium_crypto_box($message, $nonce, $alice_to_bob)),
            bin2hex(ParagonIE_Sodium_Compat::crypto_box($message, $nonce, $alice_to_bob)),
            'box'
        );
        $this->assertSame(
            $message,
            ParagonIE_Sodium_Compat::crypto_box_open(
                sodium_crypto_box($message, $nonce, $alice_to_bob),
                $nonce,
                $bob_to_alice
            )
        );

        $message = str_repeat("Lorem ipsum dolor sit amet, consectetur adipiscing elit. ", 8);
        $this->assertSame(
            bin2hex(sodium_crypto_box($message, $nonce, $alice_to_bob)),
            bin2hex(ParagonIE_Sodium_Compat::crypto_box($message, $nonce, $alice_to_bob)),
            'crypto_box is failing with large messages'
        );
        $this->assertSame(
            bin2hex($message),
            bin2hex(
                ParagonIE_Sodium_Compat::crypto_box_open(
                    sodium_crypto_box($message, $nonce, $alice_to_bob),
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
        $anonymous_message_to_alice = sodium_crypto_box_seal(
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
            $sealed_to_alice1 = sodium_crypto_box_seal($message, $alice_box_publickey);
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
                bin2hex(sodium_crypto_box_seal_open($sealed_to_alice1, $alice_box_kp)),
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
                bin2hex(sodium_crypto_box_seal_open($sealed_to_alice1, $alice_box_kp)),
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
                bin2hex(sodium_crypto_box_seal_open($sealed_to_alice2, $alice_box_kp)),
                bin2hex($message),
                'Decryption failed #2: ' . $message
            );
            $this->assertSame(
                bin2hex(sodium_crypto_box_seal_open($sealed_to_alice2, $alice_box_kp)),
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
            bin2hex(sodium_crypto_generichash('apple')),
            bin2hex(ParagonIE_Sodium_Compat::crypto_generichash('apple')),
            'BLAKE2b implementation'
        );

        $this->assertSame(
            bin2hex(sodium_crypto_generichash('apple', 'catastrophic failure')),
            bin2hex(ParagonIE_Sodium_Compat::crypto_generichash('apple', 'catastrophic failure')),
            'BLAKE2b with a key'
        );

        $this->assertSame(
            bin2hex(sodium_crypto_generichash('apple', '', 64)),
            bin2hex(ParagonIE_Sodium_Compat::crypto_generichash('apple', '', 64)),
            'BLAKE2b implementation with output length'
        );

        $this->assertSame(
            bin2hex(sodium_crypto_generichash('apple', 'catastrophic failure', 24)),
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
        $ctx = sodium_crypto_generichash_init($key);
        $nativeCtx = '';
        for ($i = 0; $i < ParagonIE_Sodium_Core_Util::strlen($ctx); ++$i) {
            $nativeCtx .= $ctx[$i];
        }
        sodium_crypto_generichash_update($nativeCtx, 'Paragon Initiative');
        ParagonIE_Sodium_Compat::crypto_generichash_update($ctx, 'Paragon Initiative');

        sodium_crypto_generichash_update($nativeCtx, ' Enterprises, LLC');
        ParagonIE_Sodium_Compat::crypto_generichash_update($ctx, ' Enterprises, LLC');

        $this->assertSame(
            bin2hex(sodium_crypto_generichash_final($nativeCtx, 32)),
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
        $kp = sodium_crypto_sign_seed_keypair($seed);
        $this->assertSame(
            bin2hex($kp),
            bin2hex(
                ParagonIE_Sodium_Compat::crypto_sign_seed_keypair($seed)
            ),
            'crypto_sign_seed_keypair() is invalid.'
        );
        $secret = sodium_crypto_sign_secretkey($kp);
        $public = sodium_crypto_sign_publickey($kp);

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
        $secret = sodium_crypto_sign_secretkey($keypair);
        $public = sodium_crypto_sign_publickey($keypair);

        $this->assertSame(
            bin2hex($public),
            bin2hex(
                sodium_crypto_sign_publickey_from_secretkey($secret)
            ),
            'Conversion from existing secret key is failing. This is a very bad thing!'
        );

        if (is_callable('sodium_crypto_sign_ed25519_sk_to_curve25519')) {
            $this->assertSame(
                bin2hex(sodium_crypto_sign_ed25519_sk_to_curve25519($secret)),
                bin2hex(ParagonIE_Sodium_Compat::crypto_sign_ed25519_sk_to_curve25519($secret)),
                'crypto_sign_ed25519_sk_to_curve25519'
            );
        }
    }

    public function testSignKeypair2()
    {
        $keypair = sodium_crypto_sign_keypair();
        $secret = sodium_crypto_sign_secretkey($keypair);
        $public = sodium_crypto_sign_publickey($keypair);

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
        $secret = sodium_crypto_sign_secretkey($keypair);
        $public = sodium_crypto_sign_publickey($keypair);

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
            bin2hex(sodium_crypto_sign_detached($message, $secret)),
            'Generated different signatures'
        );

        $this->assertSame(
            bin2hex(sodium_crypto_sign_detached($message, $secret)),
            bin2hex(ParagonIE_Sodium_Compat::crypto_sign_detached($message, $secret)),
            'Generated different signatures'
        );

        $this->assertSame(
            $expected,
            bin2hex(ParagonIE_Sodium_Compat::crypto_sign_detached($message, $secret)),
            'Generated different signatures'
        );

        $message = 'Test message: ' . base64_encode(random_bytes(33));
        $keypair = sodium_crypto_sign_keypair();
        $secret = sodium_crypto_sign_secretkey($keypair);
        $public = sodium_crypto_sign_publickey($keypair);
        $public2 = ParagonIE_Sodium_Compat::crypto_sign_publickey($keypair);
        $this->assertSame($public, $public2);

        $signature = sodium_crypto_sign_detached($message, $secret);
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
        $signed = sodium_crypto_sign($message, $secret);
        $this->assertSame(
            bin2hex($signed),
            bin2hex(ParagonIE_Sodium_Compat::crypto_sign($message, $secret)),
            'Basic crypto_sign works'
        );

        $this->assertSame(
            bin2hex(sodium_crypto_sign_open($signed, $public)),
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
                bin2hex(sodium_crypto_secretbox($message, $nonce, $key)),
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
                sodium_crypto_secretbox($message, $nonce, $key),
                $nonce,
                $key
            )
        );
        $this->assertSame(
            $message,
            sodium_crypto_secretbox_open(
                ParagonIE_Sodium_Compat::crypto_secretbox($message, $nonce, $key),
                $nonce,
                $key
            )
        );
        $message = str_repeat('a', 97);
        $this->assertSame(
            bin2hex(sodium_crypto_secretbox($message, $nonce, $key)),
            bin2hex(ParagonIE_Sodium_Compat::crypto_secretbox($message, $nonce, $key)),
            'secretbox - long messages (multiple of 16)'
        );

        $message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";

        $message = str_repeat($message, 16);

        $this->assertSame(
            bin2hex(sodium_crypto_secretbox($message, $nonce, $key)),
            bin2hex(ParagonIE_Sodium_Compat::crypto_secretbox($message, $nonce, $key)),
            'secretbox - long messages (multiple of 16)'
        );

        $message .= 'a';

        $this->assertSame(
            bin2hex(sodium_crypto_secretbox($message, $nonce, $key)),
            bin2hex(ParagonIE_Sodium_Compat::crypto_secretbox($message, $nonce, $key)),
            'secretbox - long messages (NOT a multiple of 16)'
        );

        $message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";

        $this->assertSame(
            bin2hex(sodium_crypto_secretbox($message, $nonce, $key)),
            bin2hex(ParagonIE_Sodium_Compat::crypto_secretbox($message, $nonce, $key)),
            'secretbox - medium messages'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_scalarmult_base()
     */
    public function testCryptoScalarmultBase()
    {
        $keypair = sodium_crypto_box_keypair();
        $secret = sodium_crypto_box_secretkey($keypair);
        $public = sodium_crypto_box_publickey($keypair);

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
        $alice_box_kp = sodium_crypto_box_keypair();
        $alice_box_secretkey = sodium_crypto_box_secretkey($alice_box_kp);
        $alice_box_publickey = sodium_crypto_box_publickey($alice_box_kp);

        $bob_box_kp = sodium_crypto_box_keypair();
        $bob_box_secretkey = sodium_crypto_box_secretkey($bob_box_kp);
        $bob_box_publickey = sodium_crypto_box_publickey($bob_box_kp);

        $this->assertSame(
            sodium_crypto_scalarmult($alice_box_secretkey, $bob_box_publickey),
            ParagonIE_Sodium_Compat::crypto_scalarmult($alice_box_secretkey, $bob_box_publickey)
        );

        $this->assertSame(
            sodium_crypto_scalarmult($bob_box_secretkey, $alice_box_publickey),
            ParagonIE_Sodium_Compat::crypto_scalarmult($bob_box_secretkey, $alice_box_publickey)
        );
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_box_secretkey()
     * @covers ParagonIE_Sodium_Compat::crypto_box_publickey()
     */
    public function testCryptoBoxKeypairs()
    {
        $keypair = sodium_crypto_box_keypair();
        $secret = sodium_crypto_box_secretkey($keypair);
        $public = sodium_crypto_box_publickey($keypair);

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

        $streamed = sodium_crypto_stream(64, $nonce, $key);
        $this->assertSame(
            bin2hex($streamed),
            bin2hex(ParagonIE_Sodium_Compat::crypto_stream(64, $nonce, $key)),
            'crypto_stream_xor() is not working'
        );
        $key = random_bytes(32);
        $nonce = random_bytes(24);

        $streamed = sodium_crypto_stream(1024, $nonce, $key);
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

        $streamed = sodium_crypto_stream_xor($message, $nonce, $key);
        $this->assertSame(
            bin2hex($streamed),
            bin2hex(ParagonIE_Sodium_Compat::crypto_stream_xor($message, $nonce, $key)),
            'crypto_stream_xor() is not working'
        );

        $key = random_bytes(32);
        $nonce = random_bytes(24);

        $message = 'Test message: ' . base64_encode(random_bytes(93));

        $streamed = sodium_crypto_stream_xor($message, $nonce, $key);
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
        if (!is_callable('sodium_crypto_kx')) {
            $this->markTestSkipped('sodium_crypto_kx not defined');
            return;
        }
        $alice_box_kp = sodium_crypto_box_keypair();
        $alice_box_secretkey = sodium_crypto_box_secretkey($alice_box_kp);
        $alice_box_publickey = sodium_crypto_box_publickey($alice_box_kp);

        $bob_box_kp = sodium_crypto_box_keypair();
        $bob_box_publickey = sodium_crypto_box_publickey($bob_box_kp);

        // Let's designate Bob as the server.

        $this->assertSame(
            bin2hex(
                sodium_crypto_kx(
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
     * @covers ParagonIE_Sodium_Compat::crypto_pwhash()
     *
     * @throws SodiumException
     * @throws TypeError
     */
    public function testCryptoPwhash()
    {
        if (!\extension_loaded('sodium')) {
            $this->markTestSkipped('Libsodium not loaded');
        }

        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = false;
        $passwd = 'test password';
        $salt = random_bytes(16);

        $native = \sodium_crypto_pwhash(
            16,
            $passwd,
            $salt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
        );

        $compat = ParagonIE_Sodium_Compat::crypto_pwhash(
            16,
            $passwd,
            $salt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
        );

        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;

        $this->assertSame(
            \sodium_bin2hex($native),
            \sodium_bin2hex($compat)
        );
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_kdf_derive_from_key()
     */
    public function testKdf()
    {
        $key = ParagonIE_Sodium_Compat::crypto_kdf_keygen();
        $subkey_id = random_int(1, PHP_INT_MAX);
        $context = 'NaClTest';
        $a = sodium_crypto_kdf_derive_from_key(32, $subkey_id, $context, $key);
        $b = ParagonIE_Sodium_Compat::crypto_kdf_derive_from_key(32, $subkey_id, $context, $key);
        $this->assertEquals(
            bin2hex($a),
            bin2hex($b),
            'kdf outputs differ'
        );
    }

    /**
     * @throws SodiumException
     */
    public function testPwhashNeedsRehash()
    {
        if (!\extension_loaded('sodium')) {
            $this->markTestSkipped('Libsodium not loaded');
        }
        $hash = sodium_crypto_pwhash_str(
            'test',
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
        );
        $this->assertFalse(ParagonIE_Sodium_Compat::crypto_pwhash_str_needs_rehash(
            $hash,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
        ));
        $this->assertTrue(ParagonIE_Sodium_Compat::crypto_pwhash_str_needs_rehash(
            $hash,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE << 1
        ));
        $this->assertTrue(ParagonIE_Sodium_Compat::crypto_pwhash_str_needs_rehash(
            $hash,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE + 1,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
        ));
    }

    /**
     * @throws SodiumException
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

    /**
     * Verify the _init() functions behave correctly
     *
     * @throws SodiumException
     * @throws Exception
     */
    public function testSecretStreamStates()
    {
        $key = str_repeat("A", 32);
        list($stateA, $header) = sodium_crypto_secretstream_xchacha20poly1305_init_push($key);
        $stateB = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $key);
        $this->assertEquals(bin2hex($stateA), bin2hex($stateB));

        $x = sodium_crypto_secretstream_xchacha20poly1305_push($stateA, 'test');
        $y = sodium_crypto_secretstream_xchacha20poly1305_push($stateB, 'test');
        $this->assertEquals(bin2hex($stateA), bin2hex($stateB), 'state 1');
        $this->assertEquals(bin2hex($x), bin2hex($y), 'cipher 1');

        $x = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_push($stateA, 'test');
        $y = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_push($stateB, 'test');
        $this->assertEquals(bin2hex($stateA), bin2hex($stateB), 'state 2');
        $this->assertEquals(bin2hex($x), bin2hex($y), 'cipher 2');

        // This is where things may get tricky...
        $x = sodium_crypto_secretstream_xchacha20poly1305_push($stateA, 'test');
        $y = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_push($stateB, 'test');
        $this->assertEquals(bin2hex($x), bin2hex($y), 'cipher 3');
        $this->assertEquals(bin2hex($stateA), bin2hex($stateB), 'state 3');

        // var_dump(bin2hex($stateA), bin2hex($header));

        list($stateC, $header2) = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_init_push($key);
        $stateD = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_init_pull($header2, $key);
        $this->assertEquals(bin2hex($stateC), bin2hex($stateD));
    }

    public function testSecretStream()
    {
        $key = str_repeat("A", 32);
        // list($state, $header) = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_init_push($key);
        $state = ParagonIE_Sodium_Core_Util::hex2bin(
            '5160239f7348e57e618b4a88a966ed78cb354a1e93a9bfa091f0469fc3007bf501000000280ade65e20103c20000000000000000'
        );
        $header = ParagonIE_Sodium_Core_Util::hex2bin(
            '050fbb107d2050e960ed6e9988d7b2bd280ade65e20103c2'
        );
        $state_copy = '' . $state;
        $inputs = array(
            "This is just a test message! :)",
            "Paragon Initiative Enterprises",
            "sodium_compat improves PHP code and makes PHP 7.2 migrations easy"
        );
        $outputs = array();
        $copy2 = $state_copy;
        foreach ($inputs as $i => $input) {
            $outputs[$i] = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_push($state, $input);
            $encrypt = sodium_crypto_secretstream_xchacha20poly1305_push($copy2, $input);
            $this->assertSame(bin2hex($outputs[$i]), bin2hex($encrypt), 'Ciphertext mismatch at (i = ' . $i . ')');
            $this->assertSame(bin2hex($copy2), bin2hex($state), 'state after message i = ' . $i);
        }

        $state2 = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $key);
        $this->assertSame(bin2hex($state_copy), bin2hex($state2));
        for ($i = 0; $i < count($outputs); ++$i) {
            list($decrypt, $tag) = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_pull($state_copy, $outputs[$i]);
            $this->assertEquals($inputs[$i], $decrypt, 'decrypt i = ' . $i);
            $this->assertEquals(0, $tag);
            list($decrypt, $tag) = sodium_crypto_secretstream_xchacha20poly1305_pull($state2, $outputs[$i]);
            $this->assertSame(bin2hex($state_copy), bin2hex($state2), 'state after message i = ' . $i);
            $this->assertEquals($inputs[$i], $decrypt, 'decrypt i = ' . $i);
            $this->assertEquals(0, $tag);
        }
        $this->assertSame(bin2hex($state), bin2hex($state2));
    }

    /**
     * @throws SodiumException
     * @throws Exception
     */
    public function testSodiumPad()
    {
        for ($i = 0; $i < 100; ++$i) {
            $block = random_int(16, 256);
            if (($i & 1) === 0) {
                $original = str_repeat("A", random_int(1, 1024));
            } else {
                $original = random_bytes(random_int(1, 1024));
            }

            $paddedA = sodium_pad($original, $block);
            $unpaddedA = sodium_unpad($paddedA, $block);
            $this->assertEquals($unpaddedA, $original);
            $this->assertNotEquals($paddedA, $original);

            $paddedB = ParagonIE_Sodium_Compat::pad($original, $block);
            $this->assertEquals(bin2hex($paddedA), bin2hex($paddedB), 'i = ' . $i);
            $unpaddedB = ParagonIE_Sodium_Compat::unpad($paddedB, $block);
            $this->assertEquals($unpaddedB, $original);
        }
    }

    /**
     * @throws SodiumException
     */
    public function testKeyExchange()
    {
        $alice = ParagonIE_Sodium_Compat::crypto_kx_keypair();
        $alice_pk = ParagonIE_Sodium_Compat::crypto_kx_publickey($alice);
        $bob = ParagonIE_Sodium_Compat::crypto_kx_keypair();
        $bob_pk = ParagonIE_Sodium_Compat::crypto_kx_publickey($bob);

        $alice_to_bob = ParagonIE_Sodium_Compat::crypto_kx_client_session_keys($alice, $bob_pk);
        $bob_to_alice = ParagonIE_Sodium_Compat::crypto_kx_server_session_keys($bob, $alice_pk);

        $this->assertEquals($alice_to_bob[0], $bob_to_alice[1]);
        $this->assertEquals($alice_to_bob[1], $bob_to_alice[0]);

        $alice_to_bob2 = sodium_crypto_kx_client_session_keys($alice, $bob_pk);
        $bob_to_alice2 = sodium_crypto_kx_server_session_keys($bob, $alice_pk);

        $this->assertEquals($alice_to_bob[0], $alice_to_bob2[0]);
        $this->assertEquals($alice_to_bob[1], $alice_to_bob2[1]);
        $this->assertEquals($bob_to_alice[0], $bob_to_alice2[0]);
        $this->assertEquals($bob_to_alice[1], $bob_to_alice2[1]);
    }

    /**
     * @param string $m
     * @param string $k
     * @throws SodiumException
     */
    protected function shorthashVerify($m, $k)
    {
        $this->assertSame(
            bin2hex(sodium_crypto_shorthash($m, $k)),
            bin2hex(ParagonIE_Sodium_Compat::crypto_shorthash($m, $k))
        );
    }
}
