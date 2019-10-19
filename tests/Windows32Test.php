<?php

class Windows32Test extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        if (PHP_INT_SIZE !== 4) {
            $this->markTestSkipped('64-bit OS');
        }
        ParagonIE_Sodium_Compat::$fastMult = true;
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @throws SodiumException
     */
    public function testBlake2bPersonalizedState()
    {
        $exp = ParagonIE_Sodium_Core32_Util::hex2bin(
            '48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5e4e0d0cf4b636b35260e0d1fbf0e60ab' .
            '5e8c73cdcdbbb17e4a164a2329a9d23a0000000000000000000000000000000000000000000000000000000000000000' .
            '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' .
            '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' .
            '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' .
            '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' .
            '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' .
            '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        );

        $k = '';
        $salt = '5b6b41ed9b343fe0';
        $personal = '5126fb2a37400d2a';

        for ($h = 0; $h < 64; ++$h) {
            $k[$h] = ParagonIE_Sodium_Core32_Util::intToChr($h);
        }

        $state = ParagonIE_Sodium_Compat::crypto_generichash_init_salt_personal('', 64, $salt, $personal);

        // Chop off last 17 bytes if present because they'll throw off tests:
        $a = ParagonIE_Sodium_Core32_Util::substr($state, 0, 361);
        $b = ParagonIE_Sodium_Core32_Util::substr($exp, 0, 361);
        $this->assertEquals(
            ParagonIE_Sodium_Core32_Util::bin2hex($b),
            ParagonIE_Sodium_Core32_Util::bin2hex($a),
            'Initialized value is incorrect'
        );

        $in = '';

        for ($i = 0; $i < 64; ++$i) {
            $in .= ParagonIE_Sodium_Core32_Util::intToChr($i);
        }
        ParagonIE_Sodium_Compat::crypto_generichash_update($state, $in);

        $exp2 = ParagonIE_Sodium_Core_Util::hex2bin(
            '48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5e4e0d0cf4b636b35260e0d1fbf0e60ab' .
            '5e8c73cdcdbbb17e4a164a2329a9d23a0000000000000000000000000000000000000000000000000000000000000000' .
            '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f' .
            '303132333435363738393a3b3c3d3e3f0000000000000000000000000000000000000000000000000000000000000000' .
            '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' .
            '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' .
            '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' .
            '000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000'
        );

        // Chop off last 17 bytes if present because they'll throw off tests:
        $a = ParagonIE_Sodium_Core32_Util::substr($state, 0, 361);
        $b = ParagonIE_Sodium_Core32_Util::substr($exp2, 0, 361);
        $this->assertEquals(
            ParagonIE_Sodium_Core32_Util::bin2hex($b),
            ParagonIE_Sodium_Core32_Util::bin2hex($a),
            'Updated value is incorrect'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_auth()
     * @covers ParagonIE_Sodium_Compat::crypto_auth_verify()
     * @throws SodiumException
     * @throws TypeError
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
        $this->assertFalse(
            ParagonIE_Sodium_Compat::crypto_auth_verify($mac, $message . 'wrong', $key),
            bin2hex($message) . ' == ' . bin2hex($message . 'wrong')
        );
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_decrypt()
     * @covers ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_encrypt()
     * @throws SodiumException
     * @throws TypeError
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
     * @covers ParagonIE_Sodium_Crypto::aead_chacha20poly1305_ietf_encrypt()
     * @covers ParagonIE_Sodium_Crypto::aead_chacha20poly1305_ietf_decrypt()
     * @throws SodiumException
     * @throws TypeError
     */
    public function testChapolyIetf()
    {
        $preTest = ParagonIE_Sodium_Core32_ChaCha20::ietfStream(
            32,
            ParagonIE_Sodium_Core_Util::hex2bin("0000000050532d4d73673035"),
            ParagonIE_Sodium_Core_Util::hex2bin("846394900c6c826431361885cfbedf4ec77c44f3022b13e9a7d0200728f0a0e1")
        );
        $this->assertSame(
            "b5adc0b6453dc145fe24a66f3ddd0a63760db777370663447eb78c0b1eaef49f",
            bin2hex($preTest),
            'ietfStream'
        );


        //SessionKey
        $sessionKey = ParagonIE_Sodium_Core_Util::hex2bin(
            "846394900c6c826431361885cfbedf4ec77c44f3022b13e9a7d0200728f0a0e1"
        );

        //Encrypted
        $encrypted = ParagonIE_Sodium_Core_Util::hex2bin(
            "0ffb01f94450b6803ab9fa5994d4e6242c04ac312c8aae2c8de0effd54a0db9a867ee101bfc5ebb235d734edba3c27f299d81644c1bc7b6ca4802550c29d7b28f10e5f5721bcbad2330337b2b64072fb1ead0de5d4923568c6bae5d1cd6ac528ab4d9fda97fa612ffcac0ad68f79b1578b4f1ea1d241b49aff3c71ca0a6e1c1ede16903136baa3f1c4e38e6e021a697a5fd5fd4f7df199b54c6c"
        );

        // Decrypted
        $decrypted = ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt(
            $encrypted,
            "",
            "\0\0\0\0PS-Msg05",
            $sessionKey
        );

        // Encrypt and verify with test data
        $reEncrypted = ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_encrypt(
            $decrypted,
            "",
            "\0\0\0\0PS-Msg05",
            $sessionKey
        );

        $this->assertSame(
            bin2hex($encrypted),
            bin2hex($reEncrypted)
        );

        $invalid = ParagonIE_Sodium_Core_Util::hex2bin(
            "0ffb01f94450b6803ab9fa5994d4e6242c04ac312c8aae2c8de0effd54a0db9a867ee101bfc5ebb235d734edba3c27f299d81644c1bc7b6ca4802550c29d7b28f10e5f5721bcbad2330337b2b64072fb1ead0de5d4923568c6bae5d1cd6ac528ab4d9fda97fa612ffcac0ad68f79b1578b4f1ea1d241b49aff3c71ca0a6e1c1ede16903136baa3f1c4e38e6e021a697a5fd5fd4f7df199b54c6d"
        );
        try {
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt($invalid, "", "\0\0\0\0PS-Msg05", $sessionKey);
            $this->fail('Invalid MAC accepted by crypto_aead_chacha20poly1305_ietf_decrypt()');
        } catch (SodiumException $ex) {
            $this->assertSame('Invalid MAC', $ex->getMessage());
        }

        // Random test:
        $key = random_bytes(32);
        $nonce = random_bytes(12);
        $message = 'Test case.';
        $aad = 'Optional';

        $encA = ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_encrypt($message, '', $nonce, $key);
        $encB = ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_encrypt($message, $aad, $nonce, $key);

        $this->assertSame(
            $message,
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt($encA, '', $nonce, $key)
        );
        $this->assertSame(
            $message,
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt($encB, $aad, $nonce, $key)
        );

        try {
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt($encA, $aad, $nonce, $key);
            $this->fail('Invalid MAC accepted by crypto_aead_chacha20poly1305_ietf_decrypt()');
        } catch (SodiumException $ex) {
            $this->assertSame('Invalid MAC', $ex->getMessage());
        }
        try {
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt($encB, '', $nonce, $key);
            $this->fail('Invalid MAC accepted by crypto_aead_chacha20poly1305_ietf_decrypt()');
        } catch (SodiumException $ex) {
            $this->assertSame('Invalid MAC', $ex->getMessage());
        }

        // Flip bigs in the MAC:

        $end = ParagonIE_Sodium_Core_Util::strlen($encA);
        $badA = $encA;
        $badA[$end - 1] = ParagonIE_Sodium_Core_Util::intToChr(
            ParagonIE_Sodium_Core_Util::chrToInt($badA[$end - 1]) ^ 0xff
        );

        $end = ParagonIE_Sodium_Core_Util::strlen($encB);
        $badB = $encA;
        $badB[$end - 1] = ParagonIE_Sodium_Core_Util::intToChr(
            ParagonIE_Sodium_Core_Util::chrToInt($badB[$end - 1]) ^ 0xff
        );

        try {
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt($badA, '', $nonce, $key);
            $this->fail('Invalid MAC accepted by crypto_aead_chacha20poly1305_ietf_decrypt()');
        } catch (SodiumException $ex) {
            $this->assertSame('Invalid MAC', $ex->getMessage());
        }

        try {
            ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt($badB, $aad, $nonce, $key);
            $this->fail('Invalid MAC accepted by crypto_aead_chacha20poly1305_ietf_decrypt()');
        } catch (SodiumException $ex) {
            $this->assertSame('Invalid MAC', $ex->getMessage());
        }
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_decrypt()
     * @covers ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_encrypt()
     * @throws SodiumException
     * @throws TypeError
     */
    public function testXChapoly()
    {
        $message = str_repeat("\x00", 128);
        $key = str_repeat("\x00", 32);
        $nonce = str_repeat("\x00", 24);
        $ad = '';

        $this->assertSame(
            bin2hex($message),
            bin2hex(
                ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_decrypt(
                    ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_encrypt(
                        $message,
                        $ad,
                        $nonce,
                        $key
                    ),
                    $ad,
                    $nonce,
                    $key
                )
            ),
            'Blank Message decryption'
        );

        $message = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        $key = "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f" .
               "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f";
        $nonce = "\x07\x00\x00\x00\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x00\x00\x00\x00\x00\x00\x00\x00";
        $ad = "\x50\x51\x52\x53\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7";
        $expected = "\x45\x3c\x06\x93\xa7\x40\x7f\x04\xff\x4c\x56\xae\xdb\x17\xa3\xc0\xa1\xaf\xff\x01\x17\x49\x30\xfc\x22\x28\x7c\x33\xdb\xcf\x0a\xc8\xb8\x9a\xd9\x29\x53\x0a\x1b\xb3\xab\x5e\x69\xf2\x4c\x7f\x60\x70\xc8\xf8\x40\xc9\xab\xb4\xf6\x9f\xbf\xc8\xa7\xff\x51\x26\xfa\xee\xbb\xb5\x58\x05\xee\x9c\x1c\xf2\xce\x5a\x57\x26\x32\x87\xae\xc5\x78\x0f\x04\xec\x32\x4c\x35\x14\x12\x2c\xfc\x32\x31\xfc\x1a\x8b\x71\x8a\x62\x86\x37\x30\xa2\x70\x2b\xb7\x63\x66\x11\x6b\xed\x09\xe0\xfd\x5c\x6d\x84\xb6\xb0\xc1\xab\xaf\x24\x9d\x5d\xd0\xf7\xf5\xa7\xea";

        $this->assertSame(
            bin2hex($expected),
            bin2hex(ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_encrypt($message, $ad, $nonce, $key)),
            'Test vectors'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_box()
     * @covers ParagonIE_Sodium_Compat::crypto_box_open()
     * @throws SodiumException
     * @throws TypeError
     */
    public function testCryptoBox32()
    {
        $nonce = str_repeat("\x00", 24);
        $message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        $message .= str_repeat("\x20", 64);

        $alice_secret = ParagonIE_Sodium_Core32_Util::hex2bin('69f208412d8dd5db9d0c6d18512e86f0ec75665ab841372d57b042b27ef89d8c');
        $alice_public = ParagonIE_Sodium_Core32_Util::hex2bin('ac3a70ba35df3c3fae427a7c72021d68f2c1e044040b75f17313c0c8b5d4241d');
        $bob_secret = ParagonIE_Sodium_Core32_Util::hex2bin('b581fb5ae182a16f603f39270d4e3b95bc008310b727a11dd4e784a0044d461b');
        $bob_public = ParagonIE_Sodium_Core32_Util::hex2bin('e8980c86e032f1eb2975052e8d65bddd15c3b59641174ec9678a53789d92c754');

        $alice_to_bob = ParagonIE_Sodium_Crypto32::box_keypair_from_secretkey_and_publickey(
            $alice_secret,
            $bob_public
        );
        $bob_to_alice = ParagonIE_Sodium_Crypto32::box_keypair_from_secretkey_and_publickey(
            $bob_secret,
            $alice_public
        );

        $this->assertSame(
            bin2hex(ParagonIE_Sodium_Crypto32::box($message, $nonce, $bob_to_alice)),
            bin2hex(ParagonIE_Sodium_Crypto32::box($message, $nonce, $alice_to_bob)),
            'box'
        );
    }


    /**
     * @covers ParagonIE_Sodium_File::box()
     * @covers ParagonIE_Sodium_File::box_open()
     * @throws SodiumException
     * @throws TypeError
     * @throws Exception
     */
    public function testFileBox()
    {
        $randomSeed = random_bytes(32);
        $randomNonce = random_bytes(24);
        $orig = ParagonIE_Sodium_Compat::$fastMult;
        $pseudoRandom = ParagonIE_Sodium_Compat::crypto_stream(
            32, // random_int(1 << 9, 1 << 17),
            $randomNonce,
            $randomSeed
        );
        $shortMsg = 'lessthan32bytes';
        file_put_contents('plaintext-box.data', $pseudoRandom);
        file_put_contents('plaintext-box.data2', $shortMsg);

        $alice_secret = ParagonIE_Sodium_Core_Util::hex2bin(
            '69f208412d8dd5db9d0c6d18512e86f0ec75665ab841372d57b042b27ef89d8c'
        );
        $bob_public = ParagonIE_Sodium_Core_Util::hex2bin(
            'e8980c86e032f1eb2975052e8d65bddd15c3b59641174ec9678a53789d92c754'
        );

        $kp = ParagonIE_Sodium_Compat::crypto_box_keypair_from_secretkey_and_publickey($alice_secret, $bob_public);

        $raw = ParagonIE_Sodium_Compat::crypto_box(
            $pseudoRandom,
            $randomNonce,
            $kp
        );
        ParagonIE_Sodium_File::box('plaintext-box.data', 'ciphertext-box.data', $randomNonce, $kp);
        $file = file_get_contents('ciphertext-box.data');

        $this->assertSame(bin2hex($raw), bin2hex($file));

        // Also verify decryption works.
        $plain = ParagonIE_Sodium_Compat::crypto_box_open(
            $file,
            $randomNonce,
            $kp
        );
        $this->assertSame(bin2hex($pseudoRandom), bin2hex($plain));

        ParagonIE_Sodium_File::box_open('ciphertext-box.data', 'plaintext-box2.data', $randomNonce, $kp);
        $opened = file_get_contents('plaintext-box2.data');
        $this->assertSame(bin2hex($pseudoRandom), bin2hex($opened));

        $raw = ParagonIE_Sodium_Compat::crypto_box(
            $shortMsg,
            $randomNonce,
            $kp
        );
        ParagonIE_Sodium_File::box('plaintext-box.data2', 'ciphertext-box.data2', $randomNonce, $kp);
        $file = file_get_contents('ciphertext-box.data2');
        $this->assertSame(bin2hex($raw), bin2hex($file));

        // Also verify decryption works.
        $plain = ParagonIE_Sodium_Compat::crypto_box_open(
            $file,
            $randomNonce,
            $kp
        );
        $this->assertSame(bin2hex($shortMsg), bin2hex($plain));

        ParagonIE_Sodium_File::box_open('ciphertext-box.data2', 'plaintext-box2.data', $randomNonce, $kp);
        $opened = file_get_contents('plaintext-box2.data');
        $this->assertSame(bin2hex($shortMsg), bin2hex($opened));

        ParagonIE_Sodium_Compat::$fastMult = $orig;
        unlink('ciphertext-box.data');
        unlink('ciphertext-box.data2');
        unlink('plaintext-box.data');
        unlink('plaintext-box2.data');
        unlink('plaintext-box.data2');
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_box_seal()
     * @covers ParagonIE_Sodium_Compat::crypto_box_seal_open()
     * @throws SodiumException
     * @throws TypeError
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
        if (PHP_INT_SIZE === 4) {
            $sealed_to_alice =  ParagonIE_Sodium_Core_Util::hex2bin(
                '95eb5bf05ada25ee51f4158201c261a00bfb1955a9176c8c7f1a' .
                '62f299a32e54f6ebccc8ab9d2ce1b1d3710ba37d8db17aeeec0b' .
                '78fc3d32b39b79ed96f18948c5a574b8e3f8eccc2f132408c216' .
                '46f3aedae4a67fde4f77153b5458b8a6bd712dd8365534c567ec'
            );
        } else {
            $sealed_to_alice = ParagonIE_Sodium_Compat::crypto_box_seal($message, $alice_box_publickey);
        }

        $alice_opened = ParagonIE_Sodium_Compat::crypto_box_seal_open($sealed_to_alice, $alice_box_kp);
        $this->assertSame(
            $message,
            $alice_opened,
            'Decryption failed'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_secretbox()
     * @covers ParagonIE_Sodium_Compat::crypto_secretbox_open()
     * @throws SodiumException
     * @throws TypeError
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
     * @throws Exception
     */
    public function testStateSerialization()
    {
        $key = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_keygen();
        $nonce = random_bytes(12);
        $state = new ParagonIE_Sodium_Core_SecretStream_State($key, $nonce);
        $toString = $state->toString();
        $fromString = ParagonIE_Sodium_Core_SecretStream_State::fromString($toString);

        $this->assertSame(
            $state->getNonce(),
            $fromString->getNonce()
        );
        $this->assertSame(
            $state->getCounter(),
            $fromString->getCounter()
        );
        $this->assertSame(
            $state->getKey(),
            $fromString->getKey()
        );
    }

    /**
     * @throws Exception
     */
    public function testSecretStreamMain()
    {
        $key = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_keygen();
        list($pushState, $header) = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_init_push($key);
        $pullState = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_init_pull($header, $key);
        $this->assertEquals(bin2hex($pushState), bin2hex($pullState));

        $aad = '';
        for ($i = 0; $i < 20; ++$i) {
            $msg = random_bytes(1024);
            if ($i === 10) {
                $aad = 'test';
            }
            $encrypt = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_push($pushState, $msg, $aad);
            list($decrypt, $tag) = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_pull($pullState, $encrypt, $aad);
            $this->assertEquals(bin2hex($pushState), bin2hex($pullState));
            $this->assertEquals(bin2hex($msg), bin2hex($decrypt));
            $this->assertEquals(0, $tag);
        }
        ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_rekey($pushState);
        ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_rekey($pullState);
        $this->assertEquals(bin2hex($pushState), bin2hex($pullState));
    }

    /**
     * @covers ParagonIE_Sodium_Crypto::sign_verify_detached()
     * @throws SodiumException
     * @throws TypeError
     */
    public function testVerifyDetached()
    {
        $public = ParagonIE_Sodium_Core_Util::hex2bin('ee00f800ae9e986b994ec0af67fe6b017eb78704e81639eee7efa3d3a831d1bc');

        $message = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.';
        $sig = ParagonIE_Sodium_Core_Util::hex2bin(
            '36a6d2748f6ab8f76c122a562d55343cb7c6f15c8a45bd55bd8b9e9fadd2363f' .
            '370cb78fba42c550d487b9bd7413312b6490c8b3ee2cea638997172a9c8c250f'
        );
        if (PHP_INT_SIZE === 4) {
            $this->assertTrue(
                ParagonIE_Sodium_Crypto32::sign_verify_detached($sig, $message, $public),
                'Invalid signature verification checking'
            );
        } else {
            $this->assertTrue(
                ParagonIE_Sodium_Crypto::sign_verify_detached($sig, $message, $public),
                'Invalid signature verification checking'
            );
        }
    }
}
