<?php

abstract class ParagonIE_Sodium_Core_Base64_Common
{
    /**
     * Encode into Base64
     *
     * Base64 character set "[A-Z][a-z][0-9]+/"
     *
     * @param string $src
     * @return string
     * @throws TypeError
     */
    public static function encode(
        #[SensitiveParameter]
        string $src
    ): string {
        return static::doEncode($src);
    }

    /**
     * Encode into Base64, no = padding
     *
     * Base64 character set "[A-Z][a-z][0-9]+/"
     *
     * @param string $src
     * @return string
     * @throws TypeError
     */
    public static function encodeUnpadded(
        #[SensitiveParameter]
        string $src
    ): string {
        return static::doEncode($src, false);
    }

    /**
     * @param string $src
     * @param bool $pad   Include = padding?
     * @return string
     * @throws TypeError
     */
    protected static function doEncode(
        #[SensitiveParameter]
        string $src,
        bool $pad = true
    ): string {
        $dest = '';
        $srcLen = ParagonIE_Sodium_Core_Util::strlen($src);
        // Main loop (no padding):
        for ($i = 0; $i + 3 <= $srcLen; $i += 3) {
            /** @var array<int, int> $chunk */
            $chunk = unpack('C*', ParagonIE_Sodium_Core_Util::substr($src, $i, 3));
            $b0 = $chunk[1];
            $b1 = $chunk[2];
            $b2 = $chunk[3];

            $dest .=
                static::encode6Bits(               $b0 >> 2       ) .
                static::encode6Bits((($b0 << 4) | ($b1 >> 4)) & 63) .
                static::encode6Bits((($b1 << 2) | ($b2 >> 6)) & 63) .
                static::encode6Bits(  $b2                     & 63);
        }
        // The last chunk, which may have padding:
        if ($i < $srcLen) {
            /** @var array<int, int> $chunk */
            $chunk = unpack('C*', ParagonIE_Sodium_Core_Util::substr($src, $i, $srcLen - $i));
            $b0 = $chunk[1];
            if ($i + 1 < $srcLen) {
                $b1 = $chunk[2];
                $dest .=
                    static::encode6Bits($b0 >> 2) .
                    static::encode6Bits((($b0 << 4) | ($b1 >> 4)) & 63) .
                    static::encode6Bits(($b1 << 2) & 63);
                if ($pad) {
                    $dest .= '=';
                }
            } else {
                $dest .=
                    static::encode6Bits( $b0 >> 2) .
                    static::encode6Bits(($b0 << 4) & 63);
                if ($pad) {
                    $dest .= '==';
                }
            }
        }
        return $dest;
    }

    /**
     * Decode from base64 into binary
     *
     * @throws RangeException
     * @throws TypeError
     */
    public static function decode(
        #[SensitiveParameter]
        string $src,
        bool $strictPadding = false
    ): string {
        // Remove padding
        $srcLen = ParagonIE_Sodium_Core_Util::strlen($src);
        if ($srcLen === 0) {
            return '';
        }

        if ($strictPadding) {
            if (($srcLen & 3) !== 0) {
                throw new RangeException('Incorrect padding');
            }
            if ($src[$srcLen - 1] === '=') {
                $srcLen--;
                if ($src[$srcLen - 1] === '=') {
                    $srcLen--;
                }
            }
            if (($srcLen & 3) === 1) {
                throw new RangeException(
                    'Incorrect padding'
                );
            }
            if ($src[$srcLen - 1] === '=') {
                throw new RangeException(
                    'Incorrect padding'
                );
            }
        } else {
            $src = rtrim($src, '=');
            $srcLen =  ParagonIE_Sodium_Core_Util::strlen($src);
        }

        $err = 0;
        $dest = '';
        // Main loop (no padding):
        for ($i = 0; $i + 4 <= $srcLen; $i += 4) {
            /** @var array<int, int> $chunk */
            $chunk = unpack('C*', ParagonIE_Sodium_Core_Util::substr($src, $i, 4));
            $c0 = static::decode6Bits($chunk[1]);
            $c1 = static::decode6Bits($chunk[2]);
            $c2 = static::decode6Bits($chunk[3]);
            $c3 = static::decode6Bits($chunk[4]);

            $dest .= pack(
                'CCC',
                ((($c0 << 2) | ($c1 >> 4)) & 0xff),
                ((($c1 << 4) | ($c2 >> 2)) & 0xff),
                ((($c2 << 6) | $c3) & 0xff)
            );
            $err |= ($c0 | $c1 | $c2 | $c3) >> 8;
        }
        // The last chunk, which may have padding:
        if ($i < $srcLen) {
            /** @var array<int, int> $chunk */
            $chunk = unpack('C*', ParagonIE_Sodium_Core_Util::substr($src, $i, $srcLen - $i));
            $c0 = static::decode6Bits($chunk[1]);

            if ($i + 2 < $srcLen) {
                $c1 = static::decode6Bits($chunk[2]);
                $c2 = static::decode6Bits($chunk[3]);
                $dest .= pack(
                    'CC',
                    ((($c0 << 2) | ($c1 >> 4)) & 0xff),
                    ((($c1 << 4) | ($c2 >> 2)) & 0xff)
                );
                $err |= ($c0 | $c1 | $c2) >> 8;
                $err |= ($c2 & 0x03);
            } elseif ($i + 1 < $srcLen) {
                $c1 = static::decode6Bits($chunk[2]);
                $dest .= pack(
                    'C',
                    ((($c0 << 2) | ($c1 >> 4)) & 0xff)
                );
                $err |= ($c0 | $c1) >> 8;
                $err |= ($c1 & 0x0f);
            }
        }
        $check = ($err === 0);
        if (!$check) {
            throw new RangeException(
                'Base64::decode() only expects characters in the correct base64 alphabet'
            );
        }
        return $dest;
    }

    public static function decodeNoPadding(
        #[SensitiveParameter]
        string $encodedString
    ): string {
        $srcLen = strlen($encodedString);
        if ($srcLen === 0) {
            return '';
        }
        if (($srcLen & 3) === 1) {
            throw new RangeException('Incorrect padding');
        }
        if (str_contains($encodedString, '=')) {
            throw new InvalidArgumentException(
                "decodeNoPadding() doesn't tolerate padding"
            );
        }
        return static::decode($encodedString);
    }

    abstract protected static function decode6Bits(
        #[SensitiveParameter]
        int $src
    ): int;

    abstract protected static function encode6Bits(
        #[SensitiveParameter]
        int $src
    ): string;
}
