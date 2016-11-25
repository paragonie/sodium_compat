<?php

/**
 * Class ParagonIE_Sodium_Core_Util
 */
class ParagonIE_Sodium_Core_Util
{
    /**
     * Convert a binary string into a hexadecimal string without cache-timing
     * leaks
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
     * @param string $left
     * @param string $right
     * @return int
     */
    public static function compare($left, $right)
    {
        $leftLen = self::strlen($left);
        $rightLen = self::strlen($right);
        $shared = min($leftLen, $rightLen);

        $gt = 0;
        $eq = 1;
        for ($i = 0; $i < $shared; ++$i) {
            $gt |= ((($right[$i] - $left[$i]) >> 8) & $eq);
            $eq &= (($right[$i] ^ $left[$i])) >> 8;
        }
        if (!hash_equals(self::bin2hex($leftLen), self::bin2hex($rightLen))) {
            /**
             * @todo make this constant-time
             */
            if (($gt + $gt + $eq) - 1 === 0) {
                return $leftLen - $rightLen;
            }
        }
        return ($gt + $gt + $eq) - 1;
    }

    /**
     * @param string $left
     * @param string $right
     * @return int
     */
    public static function memcmp($left, $right)
    {
        if (hash_equals($left, $right)) {
            return 0;
        }
        return -1;
    }

    /**
     * Convert a hexadecimal string into a binary string without cache-timing
     * leaks
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
                    'hexEncode() only expects hexadecimal characters'
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
     * Safe string length
     *
     * @ref mbstring.func_overload
     *
     * @param string $str
     * @return int
     */
    public static function strlen($str)
    {
        if (function_exists('mb_strlen')) {
            return mb_strlen($str, '8bit');
        } else {
            return strlen($str);
        }
    }

    /**
     * Safe substring
     *
     * @ref mbstring.func_overload
     *
     * @static bool $exists
     * @param string $str
     * @param int $start
     * @param int $length
     * @return string
     * @throws TypeError
     */
    public static function substr($str, $start = 0, $length = null)
    {
        if (function_exists('mb_substr')) {
            // $length calculation above might result in a 0-length string
            if ($length === 0) {
                return '';
            }
            return mb_substr($str, $start, $length, '8bit');
        }
        if ($length === 0) {
            return '';
        }
        // Unlike mb_substr(), substr() doesn't accept NULL for length
        if ($length !== null) {
            return substr($str, $start, $length);
        } else {
            return substr($str, $start);
        }
    }
}
