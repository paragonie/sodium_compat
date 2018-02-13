<?php

class FileTest extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @covers ParagonIE_Sodium_File::box()
     * @covers ParagonIE_Sodium_File::box_open()
     * @throws SodiumException
     * @throws TypeError
     */
    public function testBox()
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

        $alice_secret = ParagonIE_Sodium_Core_Util::hex2bin('69f208412d8dd5db9d0c6d18512e86f0ec75665ab841372d57b042b27ef89d8c');
        $bob_public = ParagonIE_Sodium_Core_Util::hex2bin('e8980c86e032f1eb2975052e8d65bddd15c3b59641174ec9678a53789d92c754');

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
     * @covers ParagonIE_Sodium_File::generichash()
     * @throws SodiumException
     * @throws TypeError
     */
    public function testGenerichash()
    {
        $randomSeed = random_bytes(32);
        $randomNonce = random_bytes(24);
        $orig = ParagonIE_Sodium_Compat::$fastMult;
        $shortMsg = 'lessthan32bytes';
        $pseudoRandom = ParagonIE_Sodium_Compat::crypto_stream(
            random_int(1 << 9, 1 << 17),
            $randomNonce,
            $randomSeed
        );
        file_put_contents('plaintext-hash.data', $pseudoRandom);
        file_put_contents('plaintext-hash.data2', $shortMsg);
        $file = ParagonIE_Sodium_File::generichash('plaintext-hash.data');
        $this->assertSame(
            ParagonIE_Sodium_Compat::crypto_generichash($pseudoRandom),
            $file
        );
        $file = ParagonIE_Sodium_File::generichash('plaintext-hash.data2');
        $this->assertSame(
            ParagonIE_Sodium_Compat::crypto_generichash($shortMsg),
            $file
        );
        ParagonIE_Sodium_Compat::$fastMult = $orig;
        unlink('plaintext-hash.data');
        unlink('plaintext-hash.data2');
    }

    /**
     * @throws SodiumException
     * @throws TypeError
     * @covers ParagonIE_Sodium_File::box_seal()
     * @covers ParagonIE_Sodium_File::box_seal_open()
     */
    public function testSeal()
    {
        $randomSeed = random_bytes(32);
        $randomNonce = random_bytes(24);
        $orig = ParagonIE_Sodium_Compat::$fastMult;
        $pseudoRandom = ParagonIE_Sodium_Compat::crypto_stream(
            random_int(1 << 9, 1 << 17),
            $randomNonce,
            $randomSeed
        );
        file_put_contents('plaintext-seal.data', $pseudoRandom);
        $alice_box_publickey = ParagonIE_Sodium_Core_Util::hex2bin(
            'fb4cb34f74a928b79123333c1e63d991060244cda98affee14c3398c6d315574'
        );

        ParagonIE_Sodium_File::box_seal('plaintext-seal.data', 'ciphertext-seal.data', $alice_box_publickey);
        $file = file_get_contents('ciphertext-seal.data');

        $alice_box_kp = ParagonIE_Sodium_Core_Util::hex2bin(
            '15b36cb00213373fb3fb03958fb0cc0012ecaca112fd249d3cf0961e311caac9' .
            'fb4cb34f74a928b79123333c1e63d991060244cda98affee14c3398c6d315574'
        );
        $raw = ParagonIE_Sodium_Compat::crypto_box_seal_open($file, $alice_box_kp);
        $this->assertSame(bin2hex($pseudoRandom), bin2hex($raw));

        ParagonIE_Sodium_File::box_seal_open('ciphertext-seal.data', 'plaintext-seal2.data', $alice_box_kp);
        $opened = file_get_contents('plaintext-seal2.data');
        $this->assertSame(bin2hex($pseudoRandom), bin2hex($opened));

        ParagonIE_Sodium_Compat::$fastMult = $orig;
        unlink('plaintext-seal.data');
        unlink('plaintext-seal2.data');
        unlink('ciphertext-seal.data');
    }

    /**
     * @throws SodiumException
     * @throws TypeError
     * @covers ParagonIE_Sodium_File::secretbox()
     * @covers ParagonIE_Sodium_File::secretbox_open()
     */
    public function testSecretbox()
    {
        $randomNonce = random_bytes(24);
        $orig = ParagonIE_Sodium_Compat::$fastMult;
        $pseudoRandom = random_bytes(random_int(1, 1 << 17));
        file_put_contents('secretbox.plain', $pseudoRandom);
        $key = random_bytes(32);

        $raw = ParagonIE_Sodium_Compat::crypto_secretbox($pseudoRandom, $randomNonce, $key);
        ParagonIE_Sodium_File::secretbox('secretbox.plain', 'secretbox.cipher', $randomNonce, $key);
        $file = file_get_contents('secretbox.cipher');

        $this->assertSame(bin2hex($raw), bin2hex($file));

        ParagonIE_Sodium_File::secretbox_open('secretbox.cipher', 'secretbox.plain2', $randomNonce, $key);
        $read = file_get_contents('secretbox.plain2');
        $this->assertSame(bin2hex($pseudoRandom), bin2hex($read));

        ParagonIE_Sodium_Compat::$fastMult = $orig;
        unlink('secretbox.plain');
        unlink('secretbox.plain2');
        unlink('secretbox.cipher');
    }


    /**
     * @covers ParagonIE_Sodium_File::sign()
     * @covers ParagonIE_Sodium_File::verify()
     * @throws Exception
     * @throws SodiumException
     * @throws TypeError
     */
    public function testSignVerify()
    {
        $randomSeed = random_bytes(32);
        $randomNonce = random_bytes(24);
        $orig = ParagonIE_Sodium_Compat::$fastMult;
        $pseudoRandom = ParagonIE_Sodium_Compat::crypto_stream(
            random_int(1, 1 << 17),
            $randomNonce,
            $randomSeed
        );
        file_put_contents('random.data', $pseudoRandom);

        ParagonIE_Sodium_Compat::$fastMult = true;
        $ed25519 = ParagonIE_Sodium_Compat::crypto_sign_keypair();
        $sign_sk = ParagonIE_Sodium_Compat::crypto_sign_secretkey($ed25519);
        $sign_pk = ParagonIE_Sodium_Compat::crypto_sign_publickey($ed25519);

        $signed = ParagonIE_Sodium_Compat::crypto_sign_detached($pseudoRandom, $sign_sk);
        $stored = ParagonIE_Sodium_File::sign('random.data', $sign_sk);

        $this->assertSame(bin2hex($signed), bin2hex($stored));
        ParagonIE_Sodium_Compat::$fastMult = $orig;

        $this->assertTrue(ParagonIE_Sodium_File::verify($signed, 'random.data', $sign_pk));
        unlink('random.data');
    }
}
