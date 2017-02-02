<?php

/**
 * Class ParagonIE_Sodium_Core_Util
 */
abstract class ParagonIE_Sodium_Core_Util
{
    /**
     * Load a 3 character substring into an integer
     *
     * @internal You should not use this directly from another application
     *
     * @param string $string
     * @return int
     * @throws RangeException
     */
    public static function load_3($string)
    {
        if (self::strlen($string) < 3) {
            throw new RangeException(
                'String must be 3 bytes or more; ' . self::strlen($string) . ' given.'
            );
        }
        $result = self::chrToInt($string[0]);
        $result |= self::chrToInt($string[1]) << 8;
        $result |= self::chrToInt($string[2]) << 16;
        return $result & 0xffffff;
    }

    /**
     * Load a 4 character substring into an integer
     *
     * @internal You should not use this directly from another application
     *
     * @param string $string
     * @return int
     * @throws RangeException
     */
    public static function load_4($string)
    {
        if (self::strlen($string) < 4) {
            throw new RangeException(
                'String must be 4 bytes or more; ' . self::strlen($string) . ' given.'
            );
        }
        $result  = (self::chrToInt($string[0]) & 0xff);
        $result |= (self::chrToInt($string[1]) & 0xff) <<  8;
        $result |= (self::chrToInt($string[2]) & 0xff) << 16;
        $result |= (self::chrToInt($string[3]) & 0xff) << 24;
        return $result & 0xffffffff;
    }

    /**
     * Store a 24-bit integer into a string, treating it as big-endian.
     *
     * @internal You should not use this directly from another application
     *
     * @param int $int
     * @return string
     */
    public static function store_3($int)
    {
        return self::intToChr(($int >> 16)    & 0xff) .
            self::intToChr(($int >> 8)     & 0xff) .
            self::intToChr($int           & 0xff);
    }

    /**
     * Store a 32-bit integer into a string, treating it as big-endian.
     *
     * @internal You should not use this directly from another application
     *
     * @param int $int
     * @return string
     */
    public static function store_4($int)
    {
        return self::intToChr(($int >> 24) & 0xff) .
            self::intToChr(($int >> 16)    & 0xff) .
            self::intToChr(($int >> 8)     & 0xff) .
            self::intToChr($int           & 0xff);
    }

    /**
     * Store a 32-bit integer into a string, treating it as little-endian.
     *
     * @internal You should not use this directly from another application
     *
     * @param int $int
     * @return string
     */
    public static function store32_le($int)
    {
        return self::intToChr($int      & 0xff) .
               self::intToChr(($int >> 8)  & 0xff) .
               self::intToChr(($int >> 16) & 0xff) .
               self::intToChr(($int >> 24) & 0xff);
    }

    /**
     * Stores a 64-bit integer as an string, treating it as little-endian.
     *
     * @internal You should not use this directly from another application
     *
     * @param int $int
     * @return string
     */
    public static function store64_le($int)
    {
        if (PHP_INT_SIZE === 8) {
            return self::intToChr($int & 0xff) .
               self::intToChr(($int >>  8) & 0xff) .
               self::intToChr(($int >> 16) & 0xff) .
               self::intToChr(($int >> 24) & 0xff) .
               self::intToChr(($int >> 32) & 0xff) .
               self::intToChr(($int >> 40) & 0xff) .
               self::intToChr(($int >> 48) & 0xff) .
               self::intToChr(($int >> 52) & 0xff);
        }
        if ($int > PHP_INT_MAX) {
            list($hiB, $int) = self::numericTo64BitInteger($int);
        } else {
            $hiB = 0;
        }
        return self::intToChr($hiB & 0xff) .
           self::intToChr(($hiB >>  8) & 0xff) .
           self::intToChr(($hiB >> 16) & 0xff) .
           self::intToChr(($hiB >> 24) & 0xff) .
           self::intToChr(($int) & 0xff) .
           self::intToChr(($int >>  8) & 0xff) .
           self::intToChr(($int >> 16) & 0xff) .
           self::intToChr(($int >> 24) & 0xff);
    }

    /**
     * Convert a binary string into a hexadecimal string without cache-timing
     * leaks
     *
     * @internal You should not use this directly from another application
     *
     * @param string $bin_string (raw binary)
     * @return string
     */
    public static function bin2hex($bin_string)
    {
        $hex = '';
        $len = self::strlen($bin_string);
        for ($i = 0; $i < $len; ++$i) {
            $chunk = unpack('C', self::substr($bin_string, $i, 2));
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
     * Convert a binary string into a hexadecimal string without cache-timing
     * leaks, returning uppercase letters (as per RFC 4648)
     *
     * @internal You should not use this directly from another application
     *
     * @param string $bin_string (raw binary)
     * @return string
     */
    public static function bin2hexUpper($bin_string)
    {
        $hex = '';
        $len = self::strlen($bin_string);
        for ($i = 0; $i < $len; ++$i) {
            $chunk = unpack('C', self::substr($bin_string, $i, 2));
            $c = $chunk[1] & 0xf;
            $b = $chunk[1] >> 4;
            $hex .= pack(
                'CC',
                (55 + $b + ((($b - 10) >> 8) & ~6)),
                (55 + $c + ((($c - 10) >> 8) & ~6))
            );
        }
        return $hex;
    }

    /**
     * Compares two strings.
     *
     * @internal You should not use this directly from another application
     *
     * @param string $left
     * @param string $right
     * @param int $len
     * @return int
     */
    public static function compare($left, $right, $len = null)
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
     * @param string $left
     * @param string $right
     * @return bool
     */
    public static function hashEquals($left, $right)
    {
        if (is_callable('hash_equals')) {
            return hash_equals($left, $right);
        }
        $d = 0;
        $len = self::strlen($left);
        if ($len !== self::strlen($right)) {
            return false;
        }
        for ($i = 0; $i < $len; ++$i) {
            $d |= self::chrToInt($left) ^ self::chrToInt($right);
        }
        return $d === 0;
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param string $left
     * @param string $right
     * @return int
     */
    public static function memcmp($left, $right)
    {
        if (self::hashEquals($left, $right)) {
            return 0;
        }
        return -1;
    }

    /**
     * Convert a hexadecimal string into a binary string without cache-timing
     * leaks
     *
     * @internal You should not use this directly from another application
     *
     * @param string $hexString
     * @param bool $strictPadding
     * @return string (raw binary)
     * @throws RangeException
     */
    public static function hex2bin($hexString, $strictPadding = false)
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
            $c = $chunk[$hex_pos];
            $c_num = $c ^ 48;
            $c_num0 = ($c_num - 10) >> 8;
            $c_alpha = ($c & ~32) - 55;
            $c_alpha0 = (($c_alpha - 10) ^ ($c_alpha - 16)) >> 8;
            if (($c_num0 | $c_alpha0) === 0) {
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
     * Cache-timing-safe variant of ord()
     *
     * @internal You should not use this directly from another application
     *
     * @param string $chr
     * @return int
     */
    public static function chrToInt($chr)
    {
        $chunk = unpack('C', self::substr($chr, 0, 1));
        return $chunk[1];
    }

    /**
     * Cache-timing-safe variant of ord()
     *
     * @internal You should not use this directly from another application
     *
     * @param int $int
     * @return string
     */
    public static function intToChr($int)
    {
        return pack('C', $int);
    }

    /**
     * Turn a string into an array of integers
     *
     * @internal You should not use this directly from another application
     *
     * @param string $string
     * @return array<int, int>
     */
    public static function stringToIntArray($string)
    {
        /**
         * @var array<int, int>
         */
        $values = array_values(
            unpack('C*', $string)
        );
        return $values;
    }

    /**
     * Turn an array of integers into a string
     *
     * @internal You should not use this directly from another application
     *
     * @param array<int, int> $ints
     * @return string
     */
    public static function intArrayToString(array $ints)
    {
        $args = $ints;
        foreach ($args as $i => $v) {
            $args[$i] = $v & 0xff;
        }
        array_unshift($args, str_repeat('C', count($ints)));
        return call_user_func_array('pack', $args);
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
    public static function numericTo64BitInteger($num)
    {
        $high = 0;
        $low = $num & 0xffffffff;

        if ((+(abs($num))) >= 1) {
            if ($num > 0) {
                $high = min((+(floor($num/4294967296))), 4294967295);
            } else {
                $high = ~~((+(ceil(($num - (+((~~($num)))))/4294967296))));
            }
        }
        return array((int) $high, (int) $low);
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
    public static function strlen($str)
    {
        if (!is_string($str)) {
            throw new TypeError('String expected');
        }

        return (int) (
            self::isMbStringOverride()
                ? mb_strlen($str, '8bit')
                : strlen($str)
        );
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
     * @param int $length
     * @return string
     * @throws TypeError
     */
    public static function substr($str, $start = 0, $length = null)
    {
        if (!is_string($str)) {
            throw new TypeError('String expected');
        }

        if ($length === 0) {
            return '';
        }

        if (self::isMbStringOverride()) {
            if (PHP_VERSION_ID < 50400 && $length === null) {
                $length = self::strlen($str);
            }
            $sub = (string) mb_substr($str, $start, $length, '8bit');
        } elseif ($length === null) {
            $sub = (string) substr($str, $start);
        } else {
            $sub = (string) substr($str, $start, $length);
        }
        if (isset($sub)) {
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
     */
    public static function verify_16($a, $b)
    {
        $diff = self::strlen($a) ^ self::strlen($b);
        for ($i = 0; $i < 16; ++$i) {
            $diff |= self::chrToInt($a[$i]) ^ self::chrToInt($b[$i]);
        }
        return $diff === 0;
    }

    /**
     * Compare a 32-character byte string in constant time.
     *
     * @internal You should not use this directly from another application
     *
     * @param string $a
     * @param string $b
     * @return bool
     */
    public static function verify_32($a, $b)
    {
        $diff = self::strlen($a) ^ self::strlen($b);
        for ($i = 0; $i < 32; ++$i) {
            $diff |= self::chrToInt($a[$i]) ^ self::chrToInt($b[$i]);
        }
        return $diff === 0;
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
    public static function xorStrings($a, $b)
    {
        if (!is_string($a)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (!is_string($b)) {
            throw new TypeError('Argument 2 must be a string');
        }
        return $a ^ $b;
    }

    /**
     * Multiply two 32-bit integers
     *
     * @param int $a
     * @param int $b
     * @return int
     */
    public static function mul($a, $b)
    {
        if (ParagonIE_Sodium_Compat::$fastMult) {
            return (int) ($a * $b);
        }
        $c = 0;
        for ($i = (PHP_INT_SIZE * 8) - 1; $i >= 0; --$i) {
            $c += ((1 << $i) & $a) * $b;
        }
        return (int) $c;
    }

    /**
     * Returns whether or not mbstring.func_overload is in effect.
     *
     * @internal You should not use this directly from another application
     *
     * @return bool
     */
    protected static function isMbStringOverride()
    {
        static $mbstring = null;

        if ($mbstring === null) {
            $mbstring = extension_loaded('mbstring')
                &&
            (ini_get('mbstring.func_overload') & MB_OVERLOAD_STRING);
        }

        return $mbstring;
    }
}
