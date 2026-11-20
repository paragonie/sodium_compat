<?php

/**
 * @internal
 * @psalm-suppress PossiblyUnusedMethod
 */
final class ParagonIE_Sodium_Core_MLDSA_Field
{
    public const Q = 8380417;
    public const D = 13;
    const MU_LO  = 1836545;  // 2201172575745 & 0x1FFFFF
    const MU_MID = 1049600;  // (2201172575745 >> 21) & 0x1FFFFF

    public static function newFromSymmetric(int $x): int
    {
        $mask = $x >> 63; // -1 if negative, 0 if non-negative
        return $x + ($mask & self::Q);
    }

    public static function reduceOnce(int $r): int
    {
        $r1 = $r - self::Q;
        $correction = ((self::Q - $r - 1) >> 63) & 1;
        $mask = -$correction;
        return $r ^ ($mask & ($r ^ $r1));
    }

    public static function add(int $a, int $b): int
    {
        return self::reduceOnce($a + $b);
    }

    public static function sub(int $a, int $b): int
    {
        return self::reduceOnce($a - $b + self::Q);
    }

    public static function neg(int $a): int
    {
        return self::reduceOnce(self::Q - $a);
    }

    public static function mul(int $a, int $b): int
    {
        $x = $a * $b;

        // Inlined Barrett reduction: hi = mul64hi($x, MU)
        // MU_HI is 0, so all $x_i * MU_HI and MU_HI * $x_i terms vanish.
        $x0 = $x & 0x1FFFFF;
        $x1 = ($x >> 21) & 0x1FFFFF;
        $x2 = ($x >> 42) & 0x3FFFFF;

        $c0 = $x0 * self::MU_LO;
        $c1 = $x0 * self::MU_MID + $x1 * self::MU_LO;
        $c2 = $x1 * self::MU_MID + $x2 * self::MU_LO;
        $c3 = $x2 * self::MU_MID;
        // c4 = 0 (all terms involve MU_HI)

        $c1 += $c0 >> 21;
        $c2 += $c1 >> 21;
        $c3 += $c2 >> 21;

        $hi = (($c3 & 0x1FFFFF) >> 1) + (($c3 >> 21) << 20);

        // Barrett approximation: hi <= floor(x/Q), off by at most 1. Therefore, r is in [0, 2Q).
        // One reduceOnce is sufficient to remain in [0, Q).
        return self::reduceOnce($x - $hi * self::Q);
    }

    /**
     * @throws SodiumException
     */
    public static function div(int $numerator, int $denominator): array
    {
        $reciprocals = [
            95232  => 193703209779376,
            261888 => 70368744177664,
            190464 => 96851604889688,
            523776 => 35184372088832,
        ];

        if (!isset($reciprocals[$denominator])) {
            throw new SodiumException('invalid reciprocal');
        }
        $quo = self::mul64hi($numerator, $reciprocals[$denominator]);
        $r   = $numerator - $quo * $denominator;
        for ($i = 0; $i < 2; $i++) {
            [$quo, $r] = self::barrettCorrectDiv($quo, $r, $denominator);
        }
        return [$quo, $r];
    }

    /**
     * FIPS 204 Algorithm 35
     */
    public static function power2round(int $a): array
    {
        $r0 = $a & ((1 << self::D) - 1);
        $threshold = (1 << (self::D - 1));
        $mask = (($threshold - $r0) >> 63);

        // $adjustment = $mask & (1 << self::D);
        $r0 -= $mask & (1 << self::D);
        $r1 = ($a - $r0) >> self::D;
        return [$r1, $r0];
    }

    /**
     * FIPS 204, Algorithm 36
     *
     * @throws SodiumException
     */
    public static function decompose(int $a, int $gamma2): array
    {
        $rPlus = $a & 0xFFFFFFFF;
        $twoGamma2 = $gamma2 << 1;

        [$tmp, ] = self::div($rPlus, $twoGamma2);
        $r0 = $rPlus - ($tmp * $twoGamma2);

        // Constant-time alternative to:
        // if ($r0 > $gamma2) {
        //     $r0 -= $twoGamma2;
        // }
        $mask1 = ($gamma2 - $r0) >> 63;
        $adjustment1 = ($mask1 & $twoGamma2);
        $r0 -= $adjustment1;

        $diff = $rPlus - $r0;
        $qMinus1 = self::Q - 1;

        $temp = ($diff - $qMinus1) | ($qMinus1 - $diff);
        $mask2 = $temp >> 63;

        [$quotient,] = self::div($diff, $twoGamma2);

        $normalR1 = $quotient;
        $specialR1 = 0;
        $normalR0 = $r0;
        $specialR0 = $r0 - 1;

        $r1 = ($mask2 & $normalR1) | (~$mask2 & $specialR1);
        $r0 = ($mask2 & $normalR0) | (~$mask2 & $specialR0);

        return [$r1, $r0];
    }

    /**
     * FIPS 204, Algorithm 37
     *
     * @throws SodiumException
     */
    public static function highBits(int $a, int $gamma2): int
    {
        [$r1, ] = self::decompose($a, $gamma2);
        return $r1;
    }

    /**
     * FIPS 204, Algorithm 38
     *
     * @throws SodiumException
     */
    public static function lowBits(int $a, int $gamma2): int
    {
        [, $r0] = self::decompose($a, $gamma2);
        return $r0;
    }

    public static function infinityNorm(int $a): int
    {
        $left = $a;
        $right = self::reduceOnce(self::Q - $a);
        return $right ^ ((($left - $right) >> 31) & ($left ^ $right));
    }

    /**
     * Multiply $a * $b, returning only the upper 64 bits
     *
     * @param int $a
     * @param int $b
     * @return int
     */
    public static function mul64hi(int $a, int $b): int
    {
        $M21 = 0x1FFFFF;
        $M22 = 0x3FFFFF;

        $a0 = $a & $M21;
        $a1 = ($a >> 21) & $M21;
        $a2 = ($a >> 42) & $M22;

        $b0 = $b & $M21;
        $b1 = ($b >> 21) & $M21;
        $b2 = ($b >> 42) & $M22;

        $c0 =  $a0 * $b0;
        $c1 =  $a0 * $b1 + $a1 * $b0;
        $c2 =  $a0 * $b2 + $a1 * $b1 + $a2 * $b0;
        $c3 =  $a1 * $b2 + $a2 * $b1;
        $c4 =  $a2 * $b2;

        $c1 += $c0 >> 21;
        $c2 += $c1 >> 21;
        $c3 += $c2 >> 21;
        $c4 += $c3 >> 21;

        return (($c3 & $M21) >> 1) + (($c4 & $M21) << 20) + (($c4 >> 21)  << 41);
    }

    public static function barrettCorrectDiv(int $quo, int $r, int $d): array
    {
        $newR = $r - $d;
        // $correction = ($r >= $d) ? 1 : 0;
        $correction = (($d - $r - 1) >> 63) & 1;
        $mask = -$correction;
        $quo += $mask & 1;
        $r   = $r ^ ($mask & ($newR ^ $r));
        return [$quo, $r];
    }

    public static function symmetric(int $a): int
    {
        static $q2 = (self::Q - 1) >> 1;
        // if ($a > $q2) {
        //     $a -= $q;
        // }
        $mask = ($q2 - $a) >> 63;
        return self::reduceonce($a - (self::Q & $mask));
    }

    /**
     * FIPS 204, Algorithm 39
     *
     * @throws SodiumException
     */
    public static function makeHint(int $z, int $r, int $gamma2): int
    {
        $r1 = self::highBits($r, $gamma2);
        $v1 = self::highBits(self::add($r, self::newFromSymmetric($z)), $gamma2);
        $difference = $r1 ^ $v1;
        return (($difference | -$difference) >> 31) & 1;
    }
}
