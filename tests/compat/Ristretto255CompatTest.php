<?php

use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Class SodiumCompatTest
 */
class Ristretto255CompatTest extends TestCase
{
    /**
     * @before
     */
    #[Before]
    public function before(): void
    {
        if (!extension_loaded('sodium') && !defined('SODIUM_COMPAT_POLYFILLED_RISTRETTO255')) {
            $this->markTestSkipped('ext/sodium is not installed; skipping the compatibility test suite.');
        }
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    public function testRistrettoFromHash(): void
    {
        $seed = random_bytes(64);
        $fromhash_1 = ParagonIE_Sodium_Compat::ristretto255_from_hash($seed, true);
        $fromhash_2 = sodium_crypto_core_ristretto255_from_hash($seed);
        $this->assertSame(
            sodium_bin2hex($fromhash_1),
            sodium_bin2hex($fromhash_2)
        );
    }

    public function testRistrettoOps(): void
    {
        $p = sodium_crypto_core_ristretto255_random();
        $q = sodium_crypto_core_ristretto255_random();

        // add
        $r1 = sodium_crypto_core_ristretto255_add($p, $q);
        $r2 = ParagonIE_Sodium_Compat::ristretto255_add($p, $q);
        $this->assertSame(sodium_bin2hex($r1), sodium_bin2hex($r2), 'add');

        // sub
        $p1 = sodium_crypto_core_ristretto255_sub($r1, $q);
        $p2 = ParagonIE_Sodium_Compat::ristretto255_sub($r2, $q);
        $this->assertSame(sodium_bin2hex($p1), sodium_bin2hex($p2), 'sub');
    }

    /**
     * @throws SodiumException
     */
    public function testRistrettoScalarOps(): void
    {
        $p = sodium_crypto_core_ristretto255_scalar_random();
        $q = sodium_crypto_core_ristretto255_scalar_random();

        // add
        $r1 = sodium_crypto_core_ristretto255_scalar_add($p, $q);
        $r2 = ParagonIE_Sodium_Compat::ristretto255_scalar_add($p, $q);
        $this->assertSame(sodium_bin2hex($r1), sodium_bin2hex($r2), 'scalar_add');

        // sub
        $p1 = sodium_crypto_core_ristretto255_scalar_sub($r1, $q);
        $p2 = ParagonIE_Sodium_Compat::ristretto255_scalar_sub($r2, $q);
        $this->assertSame(sodium_bin2hex($p1), sodium_bin2hex($p2), 'scalar_sub');

        // mul
        $z1 = sodium_crypto_core_ristretto255_scalar_mul($p, $q);
        $z2 = ParagonIE_Sodium_Compat::ristretto255_scalar_mul($p, $q);
        $this->assertSame(sodium_bin2hex($z1), sodium_bin2hex($z2), 'scalar_mul');

        // complement
        $comp1 = sodium_crypto_core_ristretto255_scalar_complement($p1);
        $comp2 = ParagonIE_Sodium_Compat::ristretto255_scalar_complement($p2);
        $this->assertSame(sodium_bin2hex($comp1), sodium_bin2hex($comp2), 'scalar_complement');

        // invert
        $inv1 = sodium_crypto_core_ristretto255_scalar_invert($p1);
        $inv2 = ParagonIE_Sodium_Compat::ristretto255_scalar_invert($p2);
        $this->assertSame(sodium_bin2hex($inv1), sodium_bin2hex($inv2), 'scalar_invert');

        // negate
        $neg1 = sodium_crypto_core_ristretto255_scalar_negate($p1);
        $neg2 = ParagonIE_Sodium_Compat::ristretto255_scalar_negate($p2);
        $this->assertSame(sodium_bin2hex($neg1), sodium_bin2hex($neg2), 'scalar_negate');

        // negate
        $bytes = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_CORE_RISTRETTO255_NONREDUCEDSCALARBYTES);
        $red1 = sodium_crypto_core_ristretto255_scalar_reduce($bytes);
        $red2 = ParagonIE_Sodium_Compat::ristretto255_scalar_reduce($bytes);
        $this->assertSame(sodium_bin2hex($red1), sodium_bin2hex($red2), 'scalar_reduce');
    }

    /**
     * This follows along the example given in the libsodium documentation:
     * @link https://libsodium.gitbook.io/doc/advanced/point-arithmetic/ristretto
     *
     * The calculation MUST be the same in our implementation and in libsodium's.
     *
     * @throws SodiumException
     */
    public function testExchange(): void
    {
        $x = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_CORE_RISTRETTO255_HASHBYTES);
        $px1 = sodium_crypto_core_ristretto255_from_hash($x);
        $px2 = ParagonIE_Sodium_Compat::ristretto255_from_hash($x);
        $this->assertSame(sodium_bin2hex($px1), sodium_bin2hex($px2), 'from_hash');

        // Test basepoints
        $temp1 = sodium_crypto_scalarmult_ristretto255_base($px1);
        $temp2 = ParagonIE_Sodium_Compat::scalarmult_ristretto255_base($px2);
        $this->assertSame(sodium_bin2hex($temp1), sodium_bin2hex($temp2), 'scalarmult_base');

        // Random Scalar
        $r = sodium_crypto_core_ristretto255_scalar_random();
        $gr1 = sodium_crypto_scalarmult_ristretto255_base($r);
        $gr2 = ParagonIE_Sodium_Compat::scalarmult_ristretto255_base($r);
        $this->assertSame(sodium_bin2hex($gr1), sodium_bin2hex($gr2), 'scalarmult_base');

        $a1 = sodium_crypto_core_ristretto255_add($px1, $gr1);
        $a2 = ParagonIE_Sodium_Compat::ristretto255_add($px2, $gr2);
        $this->assertSame(sodium_bin2hex($a1), sodium_bin2hex($a2), 'add');

        $k = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_SCALARMULT_RISTRETTO255_SCALARBYTES);
        $v1 = sodium_crypto_scalarmult_ristretto255_base($k);
        $v2 = ParagonIE_Sodium_Compat::scalarmult_ristretto255_base($k);
        $this->assertSame(sodium_bin2hex($v1), sodium_bin2hex($v2), 'scalarmult_base');

        $this->assertSame(sodium_bin2hex($a1), sodium_bin2hex($a2), 'consistency check');
        $b1 = sodium_crypto_scalarmult_ristretto255($k, $a1);
        $b2 = ParagonIE_Sodium_Compat::scalarmult_ristretto255($k, $a2);

        $this->assertSame(sodium_bin2hex($b1), sodium_bin2hex($b2), 'scalarmult');

        $ir1 = sodium_crypto_core_ristretto255_scalar_negate($r);
        $ir2 = ParagonIE_Sodium_Compat::ristretto255_scalar_negate($r);
        $this->assertSame(sodium_bin2hex($ir1), sodium_bin2hex($ir2), 'negate');

        $vir1 = sodium_crypto_scalarmult_ristretto255($ir1, $v1);
        $vir2 = ParagonIE_Sodium_Compat::scalarmult_ristretto255($ir1, $v1);
        $this->assertSame(sodium_bin2hex($vir1), sodium_bin2hex($vir2), 'scalarmult inverse');
    }

    /**
     * These test cases broken on PHP 8.1
     *
     * @return string[][]
     */
    public static function brokenPHP81TestProvider(): array
    {
        return array(
            array(
                '71a330faff41651c6dfa6e4548877d2dc2b0c26056c2e7e17bfb14cf94a4b47c',
                '92d753c7b3fef8b8b553e672823db0a052d7598999a3baacd5909f0c0a6d491f',
                '0c7507876a0215c3bf5407680a7c0bef7116c9bca25deca316322d1647dff75a'
            ),
            array(
                'a57445510d01b93e6ac9b4b0df02edf58dd577c527636a508ac52a015848051c',
                '30417da32e12af747c79dd8dd239db80d6621da155abb9bcf270dfbf7f621d4f',
                '06a686c7a7ec35374f37f8f537e7e099ce60aaca1c0c009085cc5a8f43850005'
            )
        );
    }

    /**
     * @dataProvider brokenPHP81TestProvider
     * @throws SodiumException
     */
    #[DataProvider("brokenPHP81TestProvider")]
    public function testBrokenPHP81($k_hex, $a_hex, $expect): void
    {
        $k = sodium_hex2bin($k_hex);
        $a = sodium_hex2bin($a_hex);

        $b1 = sodium_crypto_scalarmult_ristretto255($k, $a);
        $b2 = ParagonIE_Sodium_Compat::scalarmult_ristretto255($k, $a);
        $this->assertSame($expect, sodium_bin2hex($b2), 'expectation failed (sodium_compat)');
        $this->assertSame($expect, sodium_bin2hex($b1), 'expectation failed (PHP 8.1)');
        $this->assertSame(sodium_bin2hex($b1), sodium_bin2hex($b2), 'consistency failed');
    }
}
