<?php

/**
 * For unit tests only!
 */
final class PQPolynomialReference
{
    public static function coefficients($q, $pattern)
    {
        $values = array_fill(0, 256, 0);
        if ($pattern === 'one') {
            $values[0] = 1;
        } elseif ($pattern === 'wrap') {
            $values[255] = $q - 1;
        } elseif ($pattern !== 'zero') {
            for ($i = 0; $i < 256; ++$i) {
                $values[$i] = $pattern === 'ramp'
                    ? ($i * 17 + 3) % $q
                    : hexdec(
                        substr(
                            hash('sha256', 'polynomial coefficient ' . $i),
                            0,
                            6
                        )
                    ) % $q;
            }
        }
        return $values;
    }

    /** Independent add-and-double modular multiplication for 32-bit tests. */
    public static function multiplyMod($a, $b, $q)
    {
        $product = 0;
        while ($b > 0) {
            if ($b & 1) {
                $product = ($product + $a) % $q;
            }
            $a = ($a + $a) % $q;
            $b >>= 1;
        }
        return $product;
    }

    /**
     * Schoolbook multiplication in Z_q[x]/(x^256 + 1)
     */
    public static function multiply(array $a, array $b, $q)
    {
        $out = array_fill(0, 256, 0);
        for ($i = 0; $i < 256; ++$i) {
            for ($j = 0; $j < 256; ++$j) {
                $index = $i + $j;
                $product = self::multiplyMod($a[$i], $b[$j], $q);
                if ($index >= 256) {
                    $index -= 256;
                    $product = -$product;
                }
                $out[$index] = (($out[$index] + $product) % $q + $q) % $q;
            }
        }
        return $out;
    }

    /** Little-endian bit stream, assembled a byte at a time. */
    public static function pack(array $coefficients, $width)
    {
        $out = '';
        $pending = 0;
        $bits = 0;
        foreach ($coefficients as $coefficient) {
            $pending |= $coefficient << $bits;
            $bits += $width;
            while ($bits >= 8) {
                $out .= chr($pending & 255);
                $pending >>= 8;
                $bits -= 8;
            }
        }
        if ($bits !== 0) {
            $out .= chr($pending & 255);
        }
        return $out;
    }
}
