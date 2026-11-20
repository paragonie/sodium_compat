<?php

/**
 * @internal
 */
abstract class ParagonIE_Sodium_Core_MLKem_FieldElement
{
    public const Q = 3329;
    private const BARRETT_MUL = 5039;   // floor(2^{24} / Q)
    private const BARRETT_SHIFT = 24;

    /** @psalm-suppress UnusedConstructor */
    private function __construct()
    {}

    /**
     * Reduce $a from [0, 2q) to [0, q)
     */
    public static function reduceOnce(int $a): int
    {
        $x = $a - self::Q;
        return $x + (($x >> 63) & self::Q);
    }

    /**
     * Barrett reduction (avoid modulo operators))
     */
    public static function reduce(int $a): int
    {
        $quotient = ($a * self::BARRETT_MUL) >> self::BARRETT_SHIFT;
        return self::reduceOnce($a - ($quotient * self::Q));
    }

    /**
     * @throws SodiumException
     */
    public static function checkReduced(int $a): int
    {
        $lt = 1 & ($a >> 63);
        $gt = 1 & ((self::Q - $a - 1) >> 63);
        if (($lt | $gt) !== 0) {
            throw new SodiumException('Unreduced field element: ' . $a);
        }
        return $a;
    }

    public static function add(int $a, int $b): int
    {
        return self::reduceOnce($a + $b);
    }

    public static function sub(int $a, int $b): int
    {
        return self::reduceOnce($a - $b + self::Q);
    }

    public static function mul(int $a, int $b): int
    {
        return self::reduce($a * $b);
    }

    public static function mulSub(
        int $a,
        int $b,
        int $c
    ): int {
        return self::reduce($a * ($b - $c + self::Q));
    }

    public static function addMul(
        int $a,
        int $b,
        int $c,
        int $d
    ): int {
        return self::reduce($a * $b + $c * $d);
    }

    /**
     * FIPS 203, Definition 4.7
     */
    public static function compress(int $x, int $d): int
    {
        $dividend = $x << $d;
        $quotient = ($dividend * self::BARRETT_MUL) >> self::BARRETT_SHIFT;
        $remainder = $dividend - $quotient * self::Q;

        // Rounding without branches
        $quotient += (1664 - $remainder) >> 63 & 1;
        $quotient += (4993 - $remainder) >> 63 & 1;

        return $quotient & ((1 << $d) - 1);
    }

    /**
     * FIPS 203, Definition 4.8
     */
    public static function decompress(int $y, int $d): int
    {
        $dividend = $y * self::Q;
        $quotient = $dividend >> $d;
        $quotient += ($dividend >> ($d - 1)) & 1;
        return $quotient;
    }
}
