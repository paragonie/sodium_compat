<?php

/**
 * Libsodium compatibility layer
 */
class ParagonIE_Sodium_Compat
{
    public static $disableFallbackForUnitTests = false;

    const LIBRARY_VERSION_MAJOR = 9;
    const LIBRARY_VERSION_MINOR = 3;
    const VERSION_STRING = 'polyfill-1.0.11';

    /**
     * @param $string
     * @return string
     */
    public function bin2hex($string)
    {
        if (self::use_fallback('bin2hex')) {
            return call_user_func(
                '\\Sodium\\bin2hex',
                array($string)
            );
        }
        return ParagonIE_Sodium_Core_Util::bin2hex($string);
    }

    /**
     * @param string $left
     * @param string $right
     * @return int
     */
    public function compare($left, $right)
    {
        if (self::use_fallback('compare')) {
            return call_user_func(
                '\\Sodium\\compare',
                array($left, $right)
            );
        }
        return ParagonIE_Sodium_Core_Util::compare($left, $right);
    }

    /**
     * @param $string
     * @return string
     */
    public function hex2bin($string)
    {
        if (self::use_fallback('hex2bin')) {
            return call_user_func(
                '\\Sodium\\hex2bin',
                array($string)
            );
        }
        return ParagonIE_Sodium_Core_Util::hex2bin($string);
    }

    /**
     * @return int
     */
    public function library_version_major()
    {
        if (self::use_fallback('hex2bin')) {
            return call_user_func('\\Sodium\\library_version_minor');
        }
        return self::LIBRARY_VERSION_MAJOR;
    }

    /**
     * @return int
     */
    public function library_version_minor()
    {
        if (self::use_fallback('library_version_minor')) {
            return call_user_func('\\Sodium\\library_version_minor');
        }
        return self::LIBRARY_VERSION_MINOR;
    }

    /**
     * @param string $left
     * @param string $right
     * @return int
     */
    public function memcmp($left, $right)
    {
        if (self::use_fallback('memcmp')) {
            return call_user_func(
                '\\Sodium\\memcmp',
                array($left, $right)
            );
        }
        return ParagonIE_Sodium_Core_Util::memcmp($left, $right);
    }

    /**
     * @param &string $var
     */
    public function memzero(&$var)
    {
        if (self::use_fallback('memzero')) {
            call_user_func(
                '\\Sodium\\memzero',
                array($var)
            );
            return;
        }
        // This is the best we can do.
        unset($var);
    }

    /**
     * @param int $numBytes
     * @return string
     */
    public static function randombytes_buf($numBytes)
    {
        if (self::use_fallback('randombytes_buf')) {
            return call_user_func(
                '\\Sodium\\randombytes_buf',
                array($numBytes)
            );
        }
        return random_bytes($numBytes);
    }

    /**
     * @param $range
     * @return int
     */
    public static function randombytes_uniform($range)
    {
        if (self::use_fallback('randombytes_uniform')) {
            return call_user_func(
                '\\Sodium\\randombytes_uniform',
                array($range)
            );
        }
        return random_int(0, $range - 1);
    }

    /**
     * @return int
     */
    public static function randombytes_random16()
    {
        if (self::use_fallback('randombytes_random16')) {
            return call_user_func('\\Sodium\\randombytes_random16');
        }
        return random_int(0, 65535);
    }

    /**
     * @return int
     */
    public static function version_string()
    {
        if (self::use_fallback('version_string')) {
            return call_user_func('\\Sodium\\version_string');
        }
        return self::VERSION_STRING;
    }

    public static function crypto_secretbox($plaintext, $nonce, $key)
    {
        if (self::use_fallback('memcmp')) {
            return call_user_func(
                '\\Sodium\\crypto_secretbox',
                array($plaintext, $nonce, $key)
            );
        }
        return ParagonIE_Sodium_Crypto::secretbox($plaintext, $nonce, $key);
    }

    /**
     * Should we use the libsodium core function instead?
     *
     * @param string $sodium_func_name
     * @return bool
     */
    protected static function use_fallback($sodium_func_name = '')
    {
        static $res = null;
        if ($res === null) {
            $res = extension_loaded('libsodium') && PHP_VERSION_ID >= 50300;
        }
        if ($res === false) {
            // No libsodium installed
            return false;
        }
        if (self::$disableFallbackForUnitTests) {
            // Don't fallback. Use the PHP implementation.
            return false;
        }
        if (!empty($sodium_func_name)) {
            return is_callable('\\Sodium\\' . $sodium_func_name);
        }
        return true;
    }
}
