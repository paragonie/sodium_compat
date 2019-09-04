<?php

class CompatTest extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    public function testIncrement()
    {
        $string = "\x00\x00\x00\x00\x00\x00\x00\x00";

        ParagonIE_Sodium_Compat::increment($string);
        $this->assertSame("0100000000000000", ParagonIE_Sodium_Core_Util::bin2hex($string));

        ParagonIE_Sodium_Compat::increment($string);
        $this->assertSame("0200000000000000", ParagonIE_Sodium_Core_Util::bin2hex($string));

        $string = "\xff\xff\x01\x20";
        ParagonIE_Sodium_Compat::increment($string);
        $this->assertSame("00000220", ParagonIE_Sodium_Core_Util::bin2hex($string));
    }

    public function testRuntimeSpeed()
    {
        if (ParagonIE_Sodium_Compat::polyfill_is_fast()) {
            $this->markTestSkipped('Polyfill is fast, no need to test this.');
            return;
        }
        $this->assertTrue(ParagonIE_Sodium_Compat::runtime_speed_test(100, 10));
    }

    /**
     *
     */
    public function testEd25519Keypairs()
    {
        $keypair = ParagonIE_Sodium_Core_Util::hex2bin(
            '73eda3c0594270f19fbed39440c15453c647987b5fd3a38164c383adfa638ebe' .
            '4bdae2767f0fc67ac0edbe3dff6b820a55e1769c740e8b9c72066828fc57434e' .
            '4bdae2767f0fc67ac0edbe3dff6b820a55e1769c740e8b9c72066828fc57434e'
        );
        $sk = ParagonIE_Sodium_Compat::crypto_sign_secretkey($keypair);
        $pk = ParagonIE_Sodium_Compat::crypto_sign_publickey($keypair);
        $this->assertSame(
            $keypair,
            ParagonIE_Sodium_Compat::crypto_sign_keypair_from_secretkey_and_publickey($sk, $pk)
        );
        try {
            ParagonIE_Sodium_Compat::crypto_sign_keypair_from_secretkey_and_publickey($pk, $sk);
            $this->fail('Order swapped should throw; it did not');
        } catch (SodiumException $ex) {
            $this->assertEquals(
                'secretkey should be SODIUM_CRYPTO_SIGN_SECRETKEYBYTES bytes',
                $ex->getMessage()
            );
        }
        try {
            ParagonIE_Sodium_Compat::crypto_sign_keypair_from_secretkey_and_publickey($sk, $sk);
            $this->fail('Invalid input accepted for public key');
        } catch (SodiumException $ex) {
            $this->assertEquals(
                'publickey should be SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES bytes',
                $ex->getMessage()
            );
        }
    }
}
