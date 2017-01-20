<?php

class FileTest extends PHPUnit_Framework_TestCase
{
    /**
     * @covers ParagonIE_Sodium_File::sign_file()
     * @covers ParagonIE_Sodium_File::verify_file()
     */
    public function testSignVerify()
    {
        $randomSeed = random_bytes(32);
        $randomNonce = random_bytes(24);
        $pseudoRandom = ParagonIE_Sodium_Compat::crypto_stream(1 << 17, $randomNonce, $randomSeed);
        file_put_contents('random.data', $pseudoRandom);

        $ed25519 = ParagonIE_Sodium_Compat::crypto_sign_keypair();
        $sign_sk = ParagonIE_Sodium_Compat::crypto_sign_secretkey($ed25519);
        $sign_pk = ParagonIE_Sodium_Compat::crypto_sign_publickey($ed25519);

        $signed = ParagonIE_Sodium_Compat::crypto_sign_detached($pseudoRandom, $sign_sk);
        $stored = ParagonIE_Sodium_File::sign_file('random.data', $sign_sk);

        $this->assertSame(bin2hex($signed), bin2hex($stored));

        $this->assertTrue(ParagonIE_Sodium_File::verify_file($signed, 'random.data', $sign_pk));
        unlink('random.data');
    }
}
