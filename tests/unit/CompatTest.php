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
     * @throws SodiumException
     * @throws Exception
     */
    public function testKeyExchange()
    {
        $alice = ParagonIE_Sodium_Compat::crypto_kx_keypair();
        $alice_pk = ParagonIE_Sodium_Compat::crypto_kx_publickey($alice);
        $bob = ParagonIE_Sodium_Compat::crypto_kx_keypair();
        $bob_pk = ParagonIE_Sodium_Compat::crypto_kx_publickey($bob);

        $alice_to_bob = ParagonIE_Sodium_Compat::crypto_kx_client_session_keys($alice, $bob_pk);
        $bob_to_alice = sodium_crypto_kx_server_session_keys($bob, $alice_pk);

        $this->assertEquals($alice_to_bob[0], $bob_to_alice[1]);
        $this->assertEquals($alice_to_bob[1], $bob_to_alice[0]);
    }

    /**
     * @throws SodiumException
     */
    public function testSodiumPad()
    {
        for ($i = 0; $i < 100; ++$i) {
            $block = random_int(16, 256);
            $original = str_repeat("A", random_int(1, 1024));

            $padded = ParagonIE_Sodium_Compat::pad($original, $block);
            $unpadded = ParagonIE_Sodium_Compat::unpad($padded, $block);
            $this->assertEquals($unpadded, $original);

            $original = random_bytes(random_int(1, 1024));
            $padded = ParagonIE_Sodium_Compat::pad($original, $block);
            $unpadded = ParagonIE_Sodium_Compat::unpad($padded, $block);
            $this->assertEquals($unpadded, $original);
        }
    }

    /**
     * @throws SodiumException
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
