<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(ParagonIE_Sodium_Core_Ed25519::class)]
class CoreEd25519Test extends TestCase
{
    /**
     * @see https://tools.ietf.org/html/rfc8032#section-7.1
     *
     * @throws Exception
     * @throws SodiumException
     */
    public function testSeedKeypair(): void
    {
        $seed = ParagonIE_Sodium_Core_Util::hex2bin(
            '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
        );
        $pk_expected = ParagonIE_Sodium_Core_Util::hex2bin(
            'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
        );

        $pk = '';
        $sk = '';
        ParagonIE_Sodium_Core_Ed25519::seed_keypair($pk, $sk, $seed);

        $this->assertSame(
            ParagonIE_Sodium_Core_Util::bin2hex($pk_expected),
            ParagonIE_Sodium_Core_Util::bin2hex($pk)
        );
        $this->assertSame(
            ParagonIE_Sodium_Core_Util::bin2hex($seed . $pk_expected),
            ParagonIE_Sodium_Core_Util::bin2hex($sk)
        );
    }

    /**
     * @see https://tools.ietf.org/html/rfc8032#section-7.1
     *
     * @throws Exception
     * @throws SodiumException
     */
    public function testSignAndVerifyDetached(): void
    {
        // Test vector 2 from RFC 8032
        $seed = ParagonIE_Sodium_Core_Util::hex2bin(
            'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7'
        );
        $msg = ParagonIE_Sodium_Core_Util::hex2bin('af82');
        $sig_expected = ParagonIE_Sodium_Core_Util::hex2bin(
            '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac' .
            '18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a'
        );

        $pk = '';
        $sk = '';
        ParagonIE_Sodium_Core_Ed25519::seed_keypair($pk, $sk, $seed);

        $signature = ParagonIE_Sodium_Core_Ed25519::sign_detached($msg, $sk);
        $this->assertSame(
            ParagonIE_Sodium_Core_Util::bin2hex($sig_expected),
            ParagonIE_Sodium_Core_Util::bin2hex($signature)
        );

        $this->assertTrue(ParagonIE_Sodium_Core_Ed25519::verify_detached($signature, $msg, $pk));

        // Test failure on tampered message
        $this->assertFalse(ParagonIE_Sodium_Core_Ed25519::verify_detached($signature, $msg . 'a', $pk));
    }

    /**
     * @throws Exception
     * @throws SodiumException
     */
    public function testSignAndOpen(): void
    {
        $pk = '';
        $sk = '';
        ParagonIE_Sodium_Core_Ed25519::seed_keypair($pk, $sk, random_bytes(32));
        $message = 'This is a test message.';

        $signed = ParagonIE_Sodium_Core_Ed25519::sign($message, $sk);
        $opened = ParagonIE_Sodium_Core_Ed25519::sign_open($signed, $pk);

        $this->assertSame($message, $opened);

        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Core_Ed25519::sign_open($signed . 'a', $pk);
    }

    /**
     * @see https://github.com/jedisct1/libsodium/blob/master/test/default/sign.c
     *
     * @throws Exception
     * @throws SodiumException
     */
    public function testPkToCurve25519(): void
    {
        $ed25519_pk = ParagonIE_Sodium_Core_Util::hex2bin(
            'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025'
        );
        $curve25519_pk_expected = ParagonIE_Sodium_Core_Util::hex2bin(
            'cbb22fc9f790bd3eba9b84680c157ca4950a9894362601701f89c3c4d9fda23a'
        );

        $curve25519_pk = ParagonIE_Sodium_Core_Ed25519::pk_to_curve25519($ed25519_pk);
        $this->assertSame(
            ParagonIE_Sodium_Core_Util::bin2hex($curve25519_pk_expected),
            ParagonIE_Sodium_Core_Util::bin2hex($curve25519_pk)
        );
    }

    /**
     * @throws Exception
     * @throws SodiumException
     */
    public function testKeypairSplit(): void
    {
        $keypair = ParagonIE_Sodium_Core_Ed25519::keypair();
        $sk = ParagonIE_Sodium_Core_Ed25519::secretkey($keypair);
        $pk = ParagonIE_Sodium_Core_Ed25519::publickey($keypair);

        $this->assertSame(64, strlen($sk));
        $this->assertSame(32, strlen($pk));
        $this->assertSame(
            ParagonIE_Sodium_Core_Util::substr($keypair, 0, 64),
            $sk
        );
        $this->assertSame(
            ParagonIE_Sodium_Core_Util::substr($keypair, 64, 32),
            $pk
        );
    }

    public function testInvalidKeyLengths(): void
    {
        $pk = str_repeat('a', 32);
        $sk = str_repeat('b', 64);
        $sig = str_repeat('c', 64);
        $seed = str_repeat('d', 32);
        $msg = 'test';

        try {
            ParagonIE_Sodium_Core_Ed25519::pk_to_curve25519(substr($pk, 1));
            $this->fail('Invalid public key length was accepted');
        } catch (SodiumException $ex) {
            $this->assertSame(
                'Argument 1 must be CRYPTO_SIGN_PUBLICKEYBYTES bytes',
                $ex->getMessage()
            );
        }

        try {
            $pk_out = '';
            $sk_out = '';
            ParagonIE_Sodium_Core_Ed25519::seed_keypair($pk_out, $sk_out, substr($seed, 1));
            $this->fail('Invalid seed length was accepted');
        } catch (SodiumException $ex) {
            $this->assertSame(
                'crypto_sign keypair seed must be CRYPTO_SIGN_SEEDBYTES bytes long',
                $ex->getMessage()
            );
        }

        try {
            ParagonIE_Sodium_Core_Ed25519::sign_detached($msg, substr($sk, 1));
            $this->fail('Invalid secret key length was accepted');
        } catch (SodiumException $ex) {
            $this->assertSame(
                'Argument 2 must be CRYPTO_SIGN_SECRETKEYBYTES long.',
                $ex->getMessage()
            );
        }

        try {
            ParagonIE_Sodium_Core_Ed25519::verify_detached(substr($sig, 1), $msg, $pk);
            $this->fail('Invalid signature length was accepted');
        } catch (SodiumException $ex) {
            $this->assertSame(
                'Argument 1 must be CRYPTO_SIGN_BYTES long',
                $ex->getMessage()
            );
        }

        try {
            ParagonIE_Sodium_Core_Ed25519::verify_detached($sig, $msg, substr($pk, 1));
            $this->fail('Invalid public key length was accepted');
        } catch (SodiumException $ex) {
            $this->assertSame(
                'Argument 3 must be CRYPTO_SIGN_PUBLICKEYBYTES long',
                $ex->getMessage()
            );
        }
    }
}
