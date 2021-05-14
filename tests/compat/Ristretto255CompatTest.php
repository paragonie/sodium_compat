<?php


/**
 * Class SodiumCompatTest
 */
class Ristretto255CompatTest extends PHPUnit_Framework_TestCase
{
    /**
     * @before
     */
    public function before()
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('ext/sodium is not installed; skipping the compatibility test suite.');
        }
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    public function testRistrettoFromHash()
    {
        $seed = random_bytes(64);
        $fromhash_1 = ParagonIE_Sodium_Compat::ristretto255_from_hash($seed, true);
        $fromhash_2 = sodium_crypto_core_ristretto255_from_hash($seed);
        $this->assertSame(
            sodium_bin2hex($fromhash_1),
            sodium_bin2hex($fromhash_2)
        );
    }

    public function testRistrettoOps()
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
    public function testRistrettoScalarOps()
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
    public function testExchange()
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

        $b1 = sodium_crypto_scalarmult_ristretto255($k, $a1);
        $b2 = ParagonIE_Sodium_Compat::scalarmult_ristretto255($k, $a2);

        $this->assertSame(sodium_bin2hex($b1), sodium_bin2hex($b2), 'scalarmult');

        $ir1 = sodium_crypto_core_ristretto255_scalar_negate($r);
        $ir2 = ParagonIE_Sodium_Compat::ristretto255_scalar_negate($r);
        $this->assertSame(sodium_bin2hex($ir1), sodium_bin2hex($ir2), 'negate');

        $vir1 = sodium_crypto_scalarmult_ristretto255($ir1, $v1);
        $vir2 = ParagonIE_Sodium_Compat::scalarmult_ristretto255($ir1, $v1);
        $this->assertSame(sodium_bin2hex($vir1), sodium_bin2hex($vir2), 'scalarmult inverse');

        $fx1 = sodium_crypto_core_ristretto255_add($b1, $vir1);
        $fx2 = ParagonIE_Sodium_Compat::ristretto255_add($b2, $vir2);
        $this->assertSame(sodium_bin2hex($fx1), sodium_bin2hex($fx2), 'add');
    }
}
