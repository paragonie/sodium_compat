<?php
declare(strict_types=1);

if (class_exists('ParagonIE_Sodium_Core_X25519', false)) {
    return;
}

/**
 * Class ParagonIE_Sodium_Core_X25519
 */
abstract class ParagonIE_Sodium_Core_X25519 extends ParagonIE_Sodium_Core_Curve25519
{
    /**
     * Alters the objects passed to this method in place.
     *
     * @internal You should not use this directly from another application
     *
     * @param ParagonIE_Sodium_Core_Curve25519_Fe $f
     * @param ParagonIE_Sodium_Core_Curve25519_Fe $g
     * @param int $b
     * @return void
     */
    public static function fe_cswap(
        ParagonIE_Sodium_Core_Curve25519_Fe $f,
        ParagonIE_Sodium_Core_Curve25519_Fe $g,
        int $b = 0
    ): void {
        $b = -$b;
        $x0 = ($f[0] ^ $g[0]) & $b;
        $x1 = ($f[1] ^ $g[1]) & $b;
        $x2 = ($f[2] ^ $g[2]) & $b;
        $x3 = ($f[3] ^ $g[3]) & $b;
        $x4 = ($f[4] ^ $g[4]) & $b;
        $x5 = ($f[5] ^ $g[5]) & $b;
        $x6 = ($f[6] ^ $g[6]) & $b;
        $x7 = ($f[7] ^ $g[7]) & $b;
        $x8 = ($f[8] ^ $g[8]) & $b;
        $x9 = ($f[9] ^ $g[9]) & $b;
        $f[0] ^= $x0;
        $f[1] ^= $x1;
        $f[2] ^= $x2;
        $f[3] ^= $x3;
        $f[4] ^= $x4;
        $f[5] ^= $x5;
        $f[6] ^= $x6;
        $f[7] ^= $x7;
        $f[8] ^= $x8;
        $f[9] ^= $x9;
        $g[0] ^= $x0;
        $g[1] ^= $x1;
        $g[2] ^= $x2;
        $g[3] ^= $x3;
        $g[4] ^= $x4;
        $g[5] ^= $x5;
        $g[6] ^= $x6;
        $g[7] ^= $x7;
        $g[8] ^= $x8;
        $g[9] ^= $x9;
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param ParagonIE_Sodium_Core_Curve25519_Fe $f
     * @return ParagonIE_Sodium_Core_Curve25519_Fe
     */
    public static function fe_mul121666(ParagonIE_Sodium_Core_Curve25519_Fe $f): ParagonIE_Sodium_Core_Curve25519_Fe
    {
        $h = array(
            self::mul($f[0], 121666, 17),
            self::mul($f[1], 121666, 17),
            self::mul($f[2], 121666, 17),
            self::mul($f[3], 121666, 17),
            self::mul($f[4], 121666, 17),
            self::mul($f[5], 121666, 17),
            self::mul($f[6], 121666, 17),
            self::mul($f[7], 121666, 17),
            self::mul($f[8], 121666, 17),
            self::mul($f[9], 121666, 17)
        );

        $carry9 = ($h[9] + (1 << 24)) >> 25;
        $h[0] += self::mul($carry9, 19, 5);
        $h[9] -= $carry9 << 25;

        $carry1 = ($h[1] + (1 << 24)) >> 25;
        $h[2] += $carry1;
        $h[1] -= $carry1 << 25;

        $carry3 = ($h[3] + (1 << 24)) >> 25;
        $h[4] += $carry3;
        $h[3] -= $carry3 << 25;

        $carry5 = ($h[5] + (1 << 24)) >> 25;
        $h[6] += $carry5;
        $h[5] -= $carry5 << 25;

        $carry7 = ($h[7] + (1 << 24)) >> 25;
        $h[8] += $carry7;
        $h[7] -= $carry7 << 25;


        $carry0 = ($h[0] + (1 << 25)) >> 26;
        $h[1] += $carry0;
        $h[0] -= $carry0 << 26;

        $carry2 = ($h[2] + (1 << 25)) >> 26;
        $h[3] += $carry2;
        $h[2] -= $carry2 << 26;

        $carry4 = ($h[4] + (1 << 25)) >> 26;
        $h[5] += $carry4;
        $h[4] -= $carry4 << 26;

        $carry6 = ($h[6] + (1 << 25)) >> 26;
        $h[7] += $carry6;
        $h[6] -= $carry6 << 26;

        $carry8 = ($h[8] + (1 << 25)) >> 26;
        $h[9] += $carry8;
        $h[8] -= $carry8 << 26;

        foreach ($h as $i => $value) {
            $h[$i] = (int) $value;
        }
        return ParagonIE_Sodium_Core_Curve25519_Fe::fromArray($h);
    }

    /**
     * @internal You should not use this directly from another application
     *
     * Inline comments preceded by # are from libsodium's ref10 code.
     *
     * @param string $n
     * @param string $p
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_scalarmult_curve25519_ref10(
        #[SensitiveParameter]
        string $n,
        #[SensitiveParameter]
        string $p
    ): string {
        $e = $n;
        $e[0] = self::intToChr(
            self::chrToInt($e[0]) & 248
        );
        $e[31] = self::intToChr(
            (self::chrToInt($e[31]) & 127) | 64
        );
        $x1 = self::fe_frombytes($p);
        $x2 = self::fe_1();
        $z2 = self::fe_0();
        $x3 = clone $x1;
        $z3 = self::fe_1();

        $swap = 0;
        for ($pos = 254; $pos >= 0; --$pos) {
            # b = e[pos / 8] >> (pos & 7);
            $b = self::chrToInt(
                    $e[$pos >> 3]
                ) >> ($pos & 7);
            $b &= 1;
            $swap ^= $b;
            self::fe_cswap($x2, $x3, $swap);
            self::fe_cswap($z2, $z3, $swap);
            $swap = $b;
            $tmp0 = self::fe_sub($x3, $z3);
            $tmp1 = self::fe_sub($x2, $z2);
            $x2 = self::fe_add($x2, $z2);
            $z2 = self::fe_add($x3, $z3);
            $z3 = self::fe_mul($tmp0, $x2);
            $z2 = self::fe_mul($z2, $tmp1);
            $tmp0 = self::fe_sq($tmp1);
            $tmp1 = self::fe_sq($x2);
            $x3 = self::fe_add($z3, $z2);
            $z2 = self::fe_sub($z3, $z2);
            $x2 = self::fe_mul($tmp1, $tmp0);
            $tmp1 = self::fe_sub($tmp1, $tmp0);
            $z2 = self::fe_sq($z2);
            $z3 = self::fe_mul121666($tmp1);
            $x3 = self::fe_sq($x3);
            $tmp0 = self::fe_add($tmp0, $z3);
            $z3 = self::fe_mul($x1, $z2);
            $z2 = self::fe_mul($tmp1, $tmp0);
        }
        self::fe_cswap($x2, $x3, $swap);
        self::fe_cswap($z2, $z3, $swap);

        $z2 = self::fe_invert($z2);
        $x2 = self::fe_mul($x2, $z2);
        return self::fe_tobytes($x2);
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param ParagonIE_Sodium_Core_Curve25519_Fe $edwardsY
     * @param ParagonIE_Sodium_Core_Curve25519_Fe $edwardsZ
     * @return ParagonIE_Sodium_Core_Curve25519_Fe
     */
    public static function edwards_to_montgomery(
        ParagonIE_Sodium_Core_Curve25519_Fe $edwardsY,
        ParagonIE_Sodium_Core_Curve25519_Fe $edwardsZ
    ): ParagonIE_Sodium_Core_Curve25519_Fe {
        $tempX = self::fe_add($edwardsZ, $edwardsY);
        $tempZ = self::fe_sub($edwardsZ, $edwardsY);
        $tempZ = self::fe_invert($tempZ);
        return self::fe_mul($tempX, $tempZ);
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param string $n
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_scalarmult_curve25519_ref10_base(
        #[SensitiveParameter]
        string $n
    ): string {
        $e = $n;
        $e[0] = self::intToChr(
            self::chrToInt($e[0]) & 248
        );
        $e[31] = self::intToChr(
            (self::chrToInt($e[31]) & 127) | 64
        );

        $A = self::ge_scalarmult_base($e);
        $pk = self::edwards_to_montgomery($A->Y, $A->Z);
        return self::fe_tobytes($pk);
    }
}
