<?php
declare(strict_types=1);

if (class_exists('ParagonIE_Sodium_Core_ChaCha20', false)) {
    return;
}

/**
 * Class ParagonIE_Sodium_Core_ChaCha20
 */
class ParagonIE_Sodium_Core_ChaCha20 extends ParagonIE_Sodium_Core_Util
{
    /**
     * Bitwise left rotation
     *
     * @internal You should not use this directly from another application
     *
     * @param int $v
     * @param int $n
     * @return int
     */
    public static function rotate(int $v, int $n): int
    {
        $v &= 0xffffffff;
        $n &= 31;
        return (int) (
            0xffffffff & (
                ($v << $n)
                    |
                ($v >> (32 - $n))
            )
        );
    }

    /**
     * The ChaCha20 quarter round function. Works on four 32-bit integers.
     *
     * @internal You should not use this directly from another application
     *
     * @param int $a
     * @param int $b
     * @param int $c
     * @param int $d
     * @return array<int, int>
     */
    protected static function quarterRound(int $a, int $b, int $c, int $d): array
    {
        /** @var int $a */
        $a = ($a + $b) & 0xffffffff;
        $d = self::rotate($d ^ $a, 16);

        /** @var int $c */
        $c = ($c + $d) & 0xffffffff;
        $b = self::rotate($b ^ $c, 12);

        /** @var int $a */
        $a = ($a + $b) & 0xffffffff;
        $d = self::rotate($d ^ $a, 8);

        /** @var int $c */
        $c = ($c + $d) & 0xffffffff;
        $b = self::rotate($b ^ $c, 7);
        return array((int) $a, (int) $b, (int) $c, (int) $d);
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param ParagonIE_Sodium_Core_ChaCha20_Ctx $ctx
     * @param string $message
     *
     * @return string
     * @throws TypeError
     * @throws SodiumException
     */
    public static function encryptBytes(
        ParagonIE_Sodium_Core_ChaCha20_Ctx $ctx,
        string $message = ''
    ): string {
        $bytes = self::strlen($message);

        $j0  = (int) $ctx[0];
        $j1  = (int) $ctx[1];
        $j2  = (int) $ctx[2];
        $j3  = (int) $ctx[3];
        $j4  = (int) $ctx[4];
        $j5  = (int) $ctx[5];
        $j6  = (int) $ctx[6];
        $j7  = (int) $ctx[7];
        $j8  = (int) $ctx[8];
        $j9  = (int) $ctx[9];
        $j10 = (int) $ctx[10];
        $j11 = (int) $ctx[11];
        $j12 = (int) $ctx[12];
        $j13 = (int) $ctx[13];
        $j14 = (int) $ctx[14];
        $j15 = (int) $ctx[15];

        $c = '';
        for (;;) {
            if ($bytes < 64) {
                $message .= str_repeat("\x00", 64 - $bytes);
            }

            $x0 =  (int) $j0;
            $x1 =  (int) $j1;
            $x2 =  (int) $j2;
            $x3 =  (int) $j3;
            $x4 =  (int) $j4;
            $x5 =  (int) $j5;
            $x6 =  (int) $j6;
            $x7 =  (int) $j7;
            $x8 =  (int) $j8;
            $x9 =  (int) $j9;
            $x10 = (int) $j10;
            $x11 = (int) $j11;
            $x12 = (int) $j12;
            $x13 = (int) $j13;
            $x14 = (int) $j14;
            $x15 = (int) $j15;

            # for (i = 20; i > 0; i -= 2) {
            for ($i = 20; $i > 0; $i -= 2) {
                list($x0, $x4, $x8, $x12) = self::quarterRound($x0, $x4, $x8, $x12);
                list($x1, $x5, $x9, $x13) = self::quarterRound($x1, $x5, $x9, $x13);
                list($x2, $x6, $x10, $x14) = self::quarterRound($x2, $x6, $x10, $x14);
                list($x3, $x7, $x11, $x15) = self::quarterRound($x3, $x7, $x11, $x15);

                list($x0, $x5, $x10, $x15) = self::quarterRound($x0, $x5, $x10, $x15);
                list($x1, $x6, $x11, $x12) = self::quarterRound($x1, $x6, $x11, $x12);
                list($x2, $x7, $x8, $x13) = self::quarterRound($x2, $x7, $x8, $x13);
                list($x3, $x4, $x9, $x14) = self::quarterRound($x3, $x4, $x9, $x14);
            }
            /** @var int $x0 */
            $x0  = ($x0 & 0xffffffff) + $j0;
            /** @var int $x1 */
            $x1  = ($x1 & 0xffffffff) + $j1;
            /** @var int $x2 */
            $x2  = ($x2 & 0xffffffff) + $j2;
            /** @var int $x3 */
            $x3  = ($x3 & 0xffffffff) + $j3;
            /** @var int $x4 */
            $x4  = ($x4 & 0xffffffff) + $j4;
            /** @var int $x5 */
            $x5  = ($x5 & 0xffffffff) + $j5;
            /** @var int $x6 */
            $x6  = ($x6 & 0xffffffff) + $j6;
            /** @var int $x7 */
            $x7  = ($x7 & 0xffffffff) + $j7;
            /** @var int $x8 */
            $x8  = ($x8 & 0xffffffff) + $j8;
            /** @var int $x9 */
            $x9  = ($x9 & 0xffffffff) + $j9;
            /** @var int $x10 */
            $x10 = ($x10 & 0xffffffff) + $j10;
            /** @var int $x11 */
            $x11 = ($x11 & 0xffffffff) + $j11;
            /** @var int $x12 */
            $x12 = ($x12 & 0xffffffff) + $j12;
            /** @var int $x13 */
            $x13 = ($x13 & 0xffffffff) + $j13;
            /** @var int $x14 */
            $x14 = ($x14 & 0xffffffff) + $j14;
            /** @var int $x15 */
            $x15 = ($x15 & 0xffffffff) + $j15;

            $x0  ^= self::load_4(self::substr($message, 0, 4));
            $x1  ^= self::load_4(self::substr($message, 4, 4));
            $x2  ^= self::load_4(self::substr($message, 8, 4));
            $x3  ^= self::load_4(self::substr($message, 12, 4));
            $x4  ^= self::load_4(self::substr($message, 16, 4));
            $x5  ^= self::load_4(self::substr($message, 20, 4));
            $x6  ^= self::load_4(self::substr($message, 24, 4));
            $x7  ^= self::load_4(self::substr($message, 28, 4));
            $x8  ^= self::load_4(self::substr($message, 32, 4));
            $x9  ^= self::load_4(self::substr($message, 36, 4));
            $x10 ^= self::load_4(self::substr($message, 40, 4));
            $x11 ^= self::load_4(self::substr($message, 44, 4));
            $x12 ^= self::load_4(self::substr($message, 48, 4));
            $x13 ^= self::load_4(self::substr($message, 52, 4));
            $x14 ^= self::load_4(self::substr($message, 56, 4));
            $x15 ^= self::load_4(self::substr($message, 60, 4));

            ++$j12;
            if ($j12 & 0xf0000000) {
                throw new SodiumException('Overflow');
            }

            $block = self::store32_le((int) ($x0  & 0xffffffff)) .
                 self::store32_le((int) ($x1  & 0xffffffff)) .
                 self::store32_le((int) ($x2  & 0xffffffff)) .
                 self::store32_le((int) ($x3  & 0xffffffff)) .
                 self::store32_le((int) ($x4  & 0xffffffff)) .
                 self::store32_le((int) ($x5  & 0xffffffff)) .
                 self::store32_le((int) ($x6  & 0xffffffff)) .
                 self::store32_le((int) ($x7  & 0xffffffff)) .
                 self::store32_le((int) ($x8  & 0xffffffff)) .
                 self::store32_le((int) ($x9  & 0xffffffff)) .
                 self::store32_le((int) ($x10 & 0xffffffff)) .
                 self::store32_le((int) ($x11 & 0xffffffff)) .
                 self::store32_le((int) ($x12 & 0xffffffff)) .
                 self::store32_le((int) ($x13 & 0xffffffff)) .
                 self::store32_le((int) ($x14 & 0xffffffff)) .
                 self::store32_le((int) ($x15 & 0xffffffff));

            /* Partial block */
            if ($bytes < 64) {
                $c .= self::substr($block, 0, $bytes);
                break;
            }

            /* Full block */
            $c .= $block;
            $bytes -= 64;
            if ($bytes <= 0) {
                break;
            }
            $message = self::substr($message, 64);
        }
        /* end for(;;) loop */

        $ctx[12] = $j12;
        $ctx[13] = $j13;
        return $c;
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param int $len
     * @param string $nonce
     * @param string $key
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function stream(int $len = 64, string $nonce = '', string $key = ''): string
    {
        return self::encryptBytes(
            new ParagonIE_Sodium_Core_ChaCha20_Ctx($key, $nonce),
            str_repeat("\x00", $len)
        );
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param int $len
     * @param string $nonce
     * @param string $key
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function ietfStream(int $len, string $nonce = '', string $key = ''): string
    {
        return self::encryptBytes(
            new ParagonIE_Sodium_Core_ChaCha20_IetfCtx($key, $nonce),
            str_repeat("\x00", $len)
        );
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param string $message
     * @param string $nonce
     * @param string $key
     * @param string $ic
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function ietfStreamXorIc(
        string $message,
        string $nonce = '',
        string $key = '',
        string $ic = ''
    ): string {
        return self::encryptBytes(
            new ParagonIE_Sodium_Core_ChaCha20_IetfCtx($key, $nonce, $ic),
            $message
        );
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param string $message
     * @param string $nonce
     * @param string $key
     * @param string $ic
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function streamXorIc(
        string $message,
        string $nonce = '',
        string $key = '',
        string $ic = ''
    ): string {
        return self::encryptBytes(
            new ParagonIE_Sodium_Core_ChaCha20_Ctx($key, $nonce, $ic),
            $message
        );
    }
}
