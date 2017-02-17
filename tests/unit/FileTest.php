<?php

class FileTest extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @covers ParagonIE_Sodium_File::secretbox_file()
     */
    public function testSecretbox()
    {
        $randomNonce = random_bytes(24);
        $orig = ParagonIE_Sodium_Compat::$fastMult;
        $pseudoRandom = random_bytes(random_int(1 << 9, 1 << 17));
        file_put_contents('secretbox.plain', $pseudoRandom);
        $key = random_bytes(32);

        $raw = ParagonIE_Sodium_Compat::crypto_secretbox($pseudoRandom, $randomNonce, $key);
        ParagonIE_Sodium_File::secretbox_file('secretbox.plain', 'secretbox.cipher', $randomNonce, $key);
        $file = file_get_contents('secretbox.cipher');

        $this->assertSame(bin2hex($raw), bin2hex($file));

        ParagonIE_Sodium_Compat::$fastMult = $orig;
        unlink('secretbox.plain');
        unlink('secretbox.cipher');
    }

    /**
     * @covers ParagonIE_Sodium_File::box_file()
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
        file_put_contents('plaintext-box.data', $pseudoRandom);

        $alice_secret = ParagonIE_Sodium_Core_Util::hex2bin('69f208412d8dd5db9d0c6d18512e86f0ec75665ab841372d57b042b27ef89d8c');
        $bob_public = ParagonIE_Sodium_Core_Util::hex2bin('e8980c86e032f1eb2975052e8d65bddd15c3b59641174ec9678a53789d92c754');

        $kp = ParagonIE_Sodium_Compat::crypto_box_keypair_from_secretkey_and_publickey($alice_secret, $bob_public);

        $raw = ParagonIE_Sodium_Compat::crypto_box(
            $pseudoRandom,
            $randomNonce,
            $kp
        );
        ParagonIE_Sodium_File::box_file('plaintext-box.data', 'ciphertext-box.data', $randomNonce, $kp);
        $file = file_get_contents('ciphertext-box.data');

        $this->assertSame(bin2hex($raw), bin2hex($file));

        // Also verify decryption works.
        $plain = ParagonIE_Sodium_Compat::crypto_box_open(
            $file,
            $randomNonce,
            $kp
        );
        $this->assertSame(bin2hex($pseudoRandom), bin2hex($plain));

        ParagonIE_Sodium_Compat::$fastMult = $orig;
        unlink('ciphertext-box.data');
        unlink('plaintext-box.data');
    }

    /**
     * @covers ParagonIE_Sodium_File::seal_file()
     */
    public function testSeal()
    {
        $randomSeed = random_bytes(32);
        $randomNonce = random_bytes(24);
        $orig = ParagonIE_Sodium_Compat::$fastMult;
        $pseudoRandom = ParagonIE_Sodium_Compat::crypto_stream(
            32, // random_int(1 << 9, 1 << 17),
            $randomNonce,
            $randomSeed
        );
        file_put_contents('plaintext-seal.data', $pseudoRandom);
        $alice_box_publickey = ParagonIE_Sodium_Core_Util::hex2bin(
            'fb4cb34f74a928b79123333c1e63d991060244cda98affee14c3398c6d315574'
        );

        ParagonIE_Sodium_File::seal_file('plaintext-seal.data', 'ciphertext-seal.data', $alice_box_publickey);
        $file = file_get_contents('ciphertext-seal.data');

        $alice_box_kp = ParagonIE_Sodium_Core_Util::hex2bin(
            '15b36cb00213373fb3fb03958fb0cc0012ecaca112fd249d3cf0961e311caac9' .
            'fb4cb34f74a928b79123333c1e63d991060244cda98affee14c3398c6d315574'
        );
        $raw = ParagonIE_Sodium_Compat::crypto_box_seal_open($file, $alice_box_kp);
        $this->assertSame(bin2hex($pseudoRandom), bin2hex($raw));

        ParagonIE_Sodium_Compat::$fastMult = $orig;
        unlink('plaintext-seal.data');
        unlink('ciphertext-seal.data');
    }

    /**
     * @covers ParagonIE_Sodium_File::sign_file()
     * @covers ParagonIE_Sodium_File::verify_file()
     */
    public function testSignVerify()
    {
        $randomSeed = random_bytes(32);
        $randomNonce = random_bytes(24);
        $orig = ParagonIE_Sodium_Compat::$fastMult;
        $pseudoRandom = ParagonIE_Sodium_Compat::crypto_stream(
            random_int(1 << 9, 1 << 17),
            $randomNonce,
            $randomSeed
        );
        file_put_contents('random.data', $pseudoRandom);

        ParagonIE_Sodium_Compat::$fastMult = true;
        $ed25519 = ParagonIE_Sodium_Compat::crypto_sign_keypair();
        $sign_sk = ParagonIE_Sodium_Compat::crypto_sign_secretkey($ed25519);
        $sign_pk = ParagonIE_Sodium_Compat::crypto_sign_publickey($ed25519);

        $signed = ParagonIE_Sodium_Compat::crypto_sign_detached($pseudoRandom, $sign_sk);
        $stored = ParagonIE_Sodium_File::sign_file('random.data', $sign_sk);

        $this->assertSame(bin2hex($signed), bin2hex($stored));
        ParagonIE_Sodium_Compat::$fastMult = $orig;

        $this->assertTrue(ParagonIE_Sodium_File::verify_file($signed, 'random.data', $sign_pk));
        unlink('random.data');
    }
}
