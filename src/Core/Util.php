<?php

if (class_exists('ParagonIE_Sodium_Core_Util', false)) {
    return;
}

/**
 * Class ParagonIE_Sodium_Core_Util
 */
abstract class ParagonIE_Sodium_Core_Util
{
    /**
     * Convert a binary string into a hexadecimal string without cache-timing
     * leaks
     *
     * @internal You should not use this directly from another application
     *
     * @param string $binaryString (raw binary)
     * @return string
     * @throws TypeError
     */
    public static function bin2hex(string $binaryString): string
    {
        $hex = '';
        $len = self::strlen($binaryString);
        for ($i = 0; $i < $len; ++$i) {
            /** @var array<int, int> $chunk */
            $chunk = unpack('C', $binaryString[$i]);
            $c = $chunk[1] & 0xf;
            $b = $chunk[1] >> 4;
            $hex .= pack(
                'CC',
                (87 + $b + ((($b - 10) >> 8) & ~38)),
                (87 + $c + ((($c - 10) >> 8) & ~38))
            );
        }
        return $hex;
    }

    /**
     * Cache-timing-safe variant of ord()
     *
     * @internal You should not use this directly from another application
     *
     * @param string $chr
     * @return int
     * @throws SodiumException
     * @throws TypeError
     */
    public static function chrToInt(string $chr): int
    {
        if (self::strlen($chr) !== 1) {
            throw new SodiumException('chrToInt() expects a string that is exactly 1 character long');
        }
        /** @var array<int, int> $chunk */
        $chunk = unpack('C', $chr);
        return $chunk[1];
    }

    /**
     * Compares two strings.
     *
     * @internal You should not use this directly from another application
     *
     * @param string $left
     * @param string $right
     * @param ?int $len
     * @return int
     * @throws SodiumException
     * @throws TypeError
     */
    public static function compare(string $left, string $right, ?int $len = null): int
    {
        $leftLen = self::strlen($left);
        $rightLen = self::strlen($right);
        if ($len === null) {
            $len = max($leftLen, $rightLen);
            $left = str_pad($left, $len, "\x00", STR_PAD_RIGHT);
            $right = str_pad($right, $len, "\x00", STR_PAD_RIGHT);
        }

        $gt = 0;
        $eq = 1;
        $i = $len;
        while ($i !== 0) {
            --$i;
            $gt |= ((self::chrToInt($right[$i]) - self::chrToInt($left[$i])) >> 8) & $eq;
            $eq &= ((self::chrToInt($right[$i]) ^ self::chrToInt($left[$i])) - 1) >> 8;
        }
        return ($gt + $gt + $eq) - 1;
    }

    /**
     * Catch hash_update() failures and throw instead of silently proceeding
     *
     * @param HashContext|resource &$hs
     * @param string $data
     * @return void
     * @throws SodiumException
     * @psalm-suppress PossiblyInvalidArgument
     */
    protected static function hash_update(&$hs, string $data): void
    {
        if (!hash_update($hs, $data)) {
            throw new SodiumException('hash_update() failed');
        }
    }

    /**
     * Convert a hexadecimal string into a binary string without cache-timing
     * leaks
     *
     * @internal You should not use this directly from another application
     *
     * @param string $hexString
     * @param string $ignore
     * @param bool $strictPadding
     * @return string (raw binary)
     * @throws RangeException
     * @throws TypeError
     */
    public static function hex2bin(string $hexString, string $ignore = '', bool $strictPadding = false): string
    {
        $hex_pos = 0;
        $bin = '';
        $c_acc = 0;
        $hex_len = self::strlen($hexString);
        $state = 0;
        if (($hex_len & 1) !== 0) {
            if ($strictPadding) {
                throw new RangeException(
                    'Expected an even number of hexadecimal characters'
                );
            } else {
                $hexString = '0' . $hexString;
                ++$hex_len;
            }
        }

        $chunk = unpack('C*', $hexString);
        while ($hex_pos < $hex_len) {
            ++$hex_pos;
            /** @var int $c */
            $c = $chunk[$hex_pos];
            $c_num = $c ^ 48;
            $c_num0 = ($c_num - 10) >> 8;
            $c_alpha = ($c & ~32) - 55;
            $c_alpha0 = (($c_alpha - 10) ^ ($c_alpha - 16)) >> 8;
            if (($c_num0 | $c_alpha0) === 0) {
                if ($ignore && $state === 0 && strpos($ignore, self::intToChr($c)) !== false) {
                    continue;
                }
                throw new RangeException(
                    'hex2bin() only expects hexadecimal characters'
                );
            }
            $c_val = ($c_num0 & $c_num) | ($c_alpha & $c_alpha0);
            if ($state === 0) {
                $c_acc = $c_val * 16;
            } else {
                $bin .= pack('C', $c_acc | $c_val);
            }
            $state ^= 1;
        }
        return $bin;
    }

    /**
     * Turn an array of integers into a string
     *
     * @internal You should not use this directly from another application
     *
     * @param array<int, int> $ints
     * @return string
     */
    public static function intArrayToString(array $ints): string
    {
        $args = $ints;
        foreach ($args as $i => $v) {
            $args[$i] = (int) ($v & 0xff);
        }
        array_unshift($args, str_repeat('C', count($ints)));
        return (string) (call_user_func_array('pack', $args));
    }

    /**
     * Cache-timing-safe variant of ord()
     *
     * @internal You should not use this directly from another application
     *
     * @param int $int
     * @return string
     * @throws TypeError
     */
    public static function intToChr(int $int): string
    {
        return pack('C', $int);
    }

    /**
     * Load a 3 character substring into an integer
     *
     * @internal You should not use this directly from another application
     *
     * @param string $string
     * @return int
     * @throws RangeException
     * @throws TypeError
     */
    public static function load_3(string $string): int
    {
        /* Input validation: */
        if (self::strlen($string) < 3) {
            throw new RangeException(
                'String must be 3 bytes or more; ' . self::strlen($string) . ' given.'
            );
        }
        /** @var array<int, int> $unpacked */
        $unpacked = unpack('V', $string . "\0");
        return (int) ($unpacked[1] & 0xffffff);
    }

    /**
     * Load a 4 character substring into an integer
     *
     * @internal You should not use this directly from another application
     *
     * @param string $string
     * @return int
     * @throws RangeException
     * @throws TypeError
     */
    public static function load_4(string $string): int
    {
        /* Input validation: */
        if (self::strlen($string) < 4) {
            throw new RangeException(
                'String must be 4 bytes or more; ' . self::strlen($string) . ' given.'
            );
        }
        /** @var array<int, int> $unpacked */
        $unpacked = unpack('V', $string);
        return (int) $unpacked[1];
    }

    /**
     * Load a 8 character substring into an integer
     *
     * @internal You should not use this directly from another application
     *
     * @param string $string
     * @return int
     * @throws RangeException
     * @throws SodiumException
     * @throws TypeError
     */
    public static function load64_le(string $string): int
    {
        /* Input validation: */
        if (self::strlen($string) < 4) {
            throw new RangeException(
                'String must be 4 bytes or more; ' . self::strlen($string) . ' given.'
            );
        }
        /** @var array<int, int> $unpacked */
        $unpacked = unpack('P', $string);
        return (int) $unpacked[1];
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param string $left
     * @param string $right
     * @return int
     * @throws SodiumException
     * @throws TypeError
     */
    public static function memcmp(string $left, string $right): int
    {
        if (hash_equals($left, $right)) {
            return 0;
        }
        return -1;
    }

    /**
     * Multiply two integers in constant-time
     *
     * Micro-architecture timing side-channels caused by how your CPU
     * implements multiplication are best prevented by never using the
     * multiplication operators and ensuring that our code always takes
     * the same number of operations to complete, regardless of the values
     * of $a and $b.
     *
     * @internal You should not use this directly from another application
     *
     * @param int $a
     * @param int $b
     * @param int $size Limits the number of operations (useful for small,
     *                  constant operands)
     * @return int
     */
    public static function mul(int $a, int $b, int $size = 0): int
    {
        if (ParagonIE_Sodium_Compat::$fastMult) {
            return (int) ($a * $b);
        }

        static $defaultSize = null;
        /** @var int $defaultSize */
        if (!$defaultSize) {
            $defaultSize = (PHP_INT_SIZE << 3) - 1;
        }
        if ($size < 1) {
            $size = $defaultSize;
        }
        /** @var int $size */

        $c = 0;

        /**
         * Mask is either -1 or 0.
         *
         * -1 in binary looks like 0x1111 ... 1111
         *  0 in binary looks like 0x0000 ... 0000
         */
        $mask = -(($b >> ($defaultSize)) & 1);

        /**
         * Ensure $b is a positive integer, without creating
         * a branching side-channel
         *
         * @var int $b
         */
        $b = ($b & ~$mask) | ($mask & -$b);

        /**
         * Unless $size is provided:
         *
         * This loop always runs 32 times when PHP_INT_SIZE is 4.
         * This loop always runs 64 times when PHP_INT_SIZE is 8.
         */
        for ($i = $size; $i >= 0; --$i) {
            $c += ($a & -($b & 1));
            $a <<= 1;
            $b >>= 1;
        }
        $c = @($c & -1);

        /**
         * If $b was negative, we then apply the same value to $c here.
         * It doesn't matter much if $a was negative; the $c += above would
         * have produced a negative integer to begin with. But a negative $b
         * makes $b >>= 1 never return 0, so we would end up with incorrect
         * results.
         *
         * The end result is what we'd expect from integer multiplication.
         */
        return (($c & ~$mask) | ($mask & -$c));
    }

    /**
     * Convert any arbitrary numbers into two 32-bit integers that represent
     * a 64-bit integer.
     *
     * @internal You should not use this directly from another application
     *
     * @param int|float $num
     * @return array<int, int>
     */
    public static function numericTo64BitInteger($num): array
    {
        $high = 0;
        /** @var int $low */
        if (PHP_INT_SIZE === 4) {
            $low = (int) $num;
        } else {
            $low = $num & 0xffffffff;
        }

        if ((+(abs($num))) >= 1) {
            if ($num > 0) {
                /** @var int $high */
                $high = min((+(floor($num/4294967296))), 4294967295);
            } else {
                $high = ~~((+(ceil(($num - (+((~~($num)))))/4294967296))));
            }
        }
        return array((int) $high, (int) $low);
    }

    /**
     * Store a 32-bit integer into a string, treating it as little-endian.
     *
     * @internal You should not use this directly from another application
     *
     * @param int $int
     * @return string
     * @throws TypeError
     */
    public static function store32_le(int $int): string
    {
        /** @var string $packed */
        $packed = pack('V', $int);
        return $packed;
    }

    /**
     * Stores a 64-bit integer as an string, treating it as little-endian.
     *
     * @internal You should not use this directly from another application
     *
     * @param int $int
     * @return string
     * @throws TypeError
     */
    public static function store64_le(int $int): string
    {
        /** @var string $packed */
        $packed = pack('P', $int);
        return $packed;
    }

    /**
     * Safe string length
     *
     * @internal You should not use this directly from another application
     *
     * @ref mbstring.func_overload
     *
     * @param string $str
     * @return int
     * @throws TypeError
     */
    public static function strlen(string $str): int
    {
        return (int) (
        self::isMbStringOverride()
            ? mb_strlen($str, '8bit')
            : strlen($str)
        );
    }

    /**
     * Turn a string into an array of integers
     *
     * @internal You should not use this directly from another application
     *
     * @param string $string
     * @return array<int, int>
     * @throws TypeError
     */
    public static function stringToIntArray(string $string): array
    {
        return array_values(unpack('C*', $string));
    }

    /**
     * Safe substring
     *
     * @internal You should not use this directly from another application
     *
     * @ref mbstring.func_overload
     *
     * @param string $str
     * @param int $start
     * @param ?int $length
     * @return string
     * @throws TypeError
     */
    public static function substr(string $str, int $start = 0, ?int $length = null): string
    {
        if ($length === 0) {
            return '';
        }

        if (self::isMbStringOverride()) {
            $sub = mb_substr($str, $start, $length, '8bit');
        } elseif ($length === null) {
            $sub = (string) substr($str, $start);
        } else {
            $sub = (string) substr($str, $start, $length);
        }
        if ($sub !== '') {
            return $sub;
        }
        return '';
    }

    /**
     * Compare a 16-character byte string in constant time.
     *
     * @internal You should not use this directly from another application
     *
     * @param string $a
     * @param string $b
     * @return bool
     *
     * @throws TypeError
     */
    public static function verify_16(string $a, string $b): bool
    {
        return hash_equals(
            self::substr($a, 0, 16),
            self::substr($b, 0, 16)
        );
    }

    /**
     * Compare a 32-character byte string in constant time.
     *
     * @internal You should not use this directly from another application
     *
     * @param string $a
     * @param string $b
     * @return bool
     * @throws TypeError
     */
    public static function verify_32(string $a, string $b): bool
    {
        return hash_equals(
            self::substr($a, 0, 32),
            self::substr($b, 0, 32)
        );
    }

    /**
     * Calculate $a ^ $b for two strings.
     *
     * @internal You should not use this directly from another application
     *
     * @param string $a
     * @param string $b
     * @return string
     * @throws TypeError
     */
    public static function xorStrings(string $a, string $b): string
    {
        return (string) ($a ^ $b);
    }

    /**
     * Returns whether or not mbstring.func_overload is in effect.
     *
     * @internal You should not use this directly from another application
     *
     * Note: MB_OVERLOAD_STRING === 2, but we don't reference the constant
     * (for nuisance-free PHP 8 support)
     *
     * @return bool
     */
    protected static function isMbStringOverride(): bool
    {
        static $mbstring = null;

        if ($mbstring === null) {
            if (!defined('MB_OVERLOAD_STRING')) {
                $mbstring = false;
                return $mbstring;
            }
            $mbstring = extension_loaded('mbstring')
                && defined('MB_OVERLOAD_STRING')
                &&
            ((int) (ini_get('mbstring.func_overload')) & 2);
            // MB_OVERLOAD_STRING === 2
        }
        /** @var bool $mbstring */

        return $mbstring;
    }
}
