<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(ParagonIE_Sodium_Core_X25519::class)]
class CoreX25519Test extends TestCase
{
    /**
     * @throws Exception
     * @throws SodiumException
     */
    public function testDiffieHellmanSymmetry(): void
    {
        $alice_sk = random_bytes(32);
        $bob_sk = random_bytes(32);

        $alice_pk = ParagonIE_Sodium_Core_X25519::crypto_scalarmult_curve25519_ref10_base($alice_sk);
        $bob_pk = ParagonIE_Sodium_Core_X25519::crypto_scalarmult_curve25519_ref10_base($bob_sk);

        $shared1 = ParagonIE_Sodium_Core_X25519::crypto_scalarmult_curve25519_ref10($alice_sk, $bob_pk);
        $shared2 = ParagonIE_Sodium_Core_X25519::crypto_scalarmult_curve25519_ref10($bob_sk, $alice_pk);

        $this->assertSame(
            ParagonIE_Sodium_Core_Util::bin2hex($shared1),
            ParagonIE_Sodium_Core_Util::bin2hex($shared2)
        );
    }

    /**
     * @throws SodiumException
     * @see https://tools.ietf.org/html/rfc7748#section-6.1
     */
    public function testRfc7748Vectors(): void
    {
        $alice_sk = ParagonIE_Sodium_Core_Util::hex2bin(
            '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'
        );
        $alice_pk_expected = ParagonIE_Sodium_Core_Util::hex2bin(
            '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'
        );

        $bob_sk = ParagonIE_Sodium_Core_Util::hex2bin(
            '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb'
        );
        $bob_pk_expected = ParagonIE_Sodium_Core_Util::hex2bin(
            'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f'
        );

        $shared_secret_expected = ParagonIE_Sodium_Core_Util::hex2bin(
            '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742'
        );

        $alice_pk = ParagonIE_Sodium_Core_X25519::crypto_scalarmult_curve25519_ref10_base($alice_sk);
        $this->assertSame(
            ParagonIE_Sodium_Core_Util::bin2hex($alice_pk_expected),
            ParagonIE_Sodium_Core_Util::bin2hex($alice_pk)
        );

        $bob_pk = ParagonIE_Sodium_Core_X25519::crypto_scalarmult_curve25519_ref10_base($bob_sk);
        $this->assertSame(
            ParagonIE_Sodium_Core_Util::bin2hex($bob_pk_expected),
            ParagonIE_Sodium_Core_Util::bin2hex($bob_pk)
        );

        $shared_secret = ParagonIE_Sodium_Core_X25519::crypto_scalarmult_curve25519_ref10($alice_sk, $bob_pk);
        $this->assertSame(
            ParagonIE_Sodium_Core_Util::bin2hex($shared_secret_expected),
            ParagonIE_Sodium_Core_Util::bin2hex($shared_secret)
        );
    }

    /**
     * @throws Exception
     * @throws SodiumException
     */
    public function testBasepointEquivalence(): void
    {
        $sk = random_bytes(32);
        $basepoint = "\x09" . str_repeat("\x00", 31);

        $pk1 = ParagonIE_Sodium_Core_X25519::crypto_scalarmult_curve25519_ref10_base($sk);
        $pk2 = ParagonIE_Sodium_Core_X25519::crypto_scalarmult_curve25519_ref10($sk, $basepoint);

        $this->assertSame(
            ParagonIE_Sodium_Core_Util::bin2hex($pk1),
            ParagonIE_Sodium_Core_Util::bin2hex($pk2)
        );
    }
}
