<?php

/**
 * Libsodium compatibility layer
 */
class ParagonIE_Sodium_Compat
{
    /**
     * @var bool
     */
    public static $disableFallbackForUnitTests = false;

    const LIBRARY_VERSION_MAJOR = 9;
    const LIBRARY_VERSION_MINOR = 3;
    const VERSION_STRING = 'polyfill-1.0.11';

    /**
     * @param $string
     * @return string
     */
    public static function bin2hex($string)
    {
        if (self::use_fallback('bin2hex')) {
            return call_user_func_array(
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
    public static function compare($left, $right)
    {
        if (self::use_fallback('compare')) {
            return call_user_func_array(
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
    public static function hex2bin($string)
    {
        if (self::use_fallback('hex2bin')) {
            return call_user_func_array(
                '\\Sodium\\hex2bin',
                array($string)
            );
        }
        return ParagonIE_Sodium_Core_Util::hex2bin($string);
    }

    /**
     * @return int
     */
    public static function library_version_major()
    {
        if (self::use_fallback('hex2bin')) {
            return (int) call_user_func('\\Sodium\\library_version_minor');
        }
        return self::LIBRARY_VERSION_MAJOR;
    }

    /**
     * @return int
     */
    public static function library_version_minor()
    {
        if (self::use_fallback('library_version_minor')) {
            return (int) call_user_func('\\Sodium\\library_version_minor');
        }
        return self::LIBRARY_VERSION_MINOR;
    }

    /**
     * @param string $left
     * @param string $right
     * @return int
     */
    public static function memcmp($left, $right)
    {
        if (self::use_fallback('memcmp')) {
            return call_user_func_array(
                '\\Sodium\\memcmp',
                array($left, $right)
            );
        }
        return ParagonIE_Sodium_Core_Util::memcmp($left, $right);
    }

    /**
     * @param &string $var
     */
    public static function memzero(&$var)
    {
        if (self::use_fallback('memzero')) {
            call_user_func_array(
                '\\Sodium\\memzero',
                array(&$var)
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
            return call_user_func_array(
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
            return (int) call_user_func_array(
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
            return (int) call_user_func('\\Sodium\\randombytes_random16');
        }
        return random_int(0, 65535);
    }

    /**
     * @return int
     */
    public static function version_string()
    {
        if (self::use_fallback('version_string')) {
            return (int) call_user_func('\\Sodium\\version_string');
        }
        return self::VERSION_STRING;
    }

    /**
     * @param $message
     * @param $key
     * @return string
     */
    public static function crypto_auth($message, $key)
    {
        if (self::use_fallback('crypto_auth')) {
            return call_user_func_array(
                '\\Sodium\\crypto_auth',
                array($message, $key)
            );
        }
        return ParagonIE_Sodium_Crypto::auth($message, $key);
    }

    /**
     * @param string $mac
     * @param string $message
     * @param string $key
     * @return bool
     */
    public static function crypto_auth_verify($mac, $message, $key)
    {
        if (self::use_fallback('crypto_auth_verify')) {
            return call_user_func_array(
                '\\Sodium\\crypto_auth_verify',
                array($mac, $message, $key)
            );
        }
        return ParagonIE_Sodium_Crypto::auth_verify($mac, $message, $key);
    }

    /**
     * @param string $plaintext
     * @param string $nonce
     * @param string $kp
     * @return string
     */
    public static function crypto_box($plaintext, $nonce, $kp)
    {
        if (self::use_fallback('crypto_box')) {
            return call_user_func_array(
                '\\Sodium\\crypto_box',
                array($plaintext, $nonce, $kp)
            );
        }
        return ParagonIE_Sodium_Crypto::box($plaintext, $nonce, $kp);
    }

    /**
     * @param string $plaintext
     * @param string $pk
     * @return string
     */
    public static function crypto_box_seal($plaintext, $pk)
    {
        if (self::use_fallback('crypto_box_seal')) {
            return call_user_func_array(
                '\\Sodium\\crypto_box_seal',
                array($plaintext, $pk)
            );
        }
        return ParagonIE_Sodium_Crypto::box_seal($plaintext, $pk);
    }

    /**
     * @param string $plaintext
     * @param string $kp
     * @return string
     */
    public static function crypto_box_seal_open($plaintext, $kp)
    {
        if (self::use_fallback('crypto_box_seal_open')) {
            return call_user_func_array(
                '\\Sodium\\crypto_box_seal_open',
                array($plaintext, $kp)
            );
        }
        return ParagonIE_Sodium_Crypto::box_seal_open($plaintext, $kp);
    }

    /**
     * @param string $kp
     * @return string
     */
    public static function crypto_box_publickey($kp)
    {
        if (self::use_fallback('crypto_box_publickey')) {
            return call_user_func_array(
                '\\Sodium\\crypto_box_publickey',
                array($kp)
            );
        }
        return ParagonIE_Sodium_Crypto::box_publickey($kp);
    }

    /**
     * @param string $sk
     * @return string
     */
    public static function crypto_box_publickey_from_secretkey($sk)
    {
        if (self::use_fallback('crypto_box_publickey_from_secretkey')) {
            return call_user_func_array(
                '\\Sodium\\crypto_box_publickey_from_secretkey',
                array($sk)
            );
        }
        return ParagonIE_Sodium_Crypto::box_publickey_from_secretkey($sk);
    }

    /**
     * @param string $kp
     * @return string
     */
    public static function crypto_box_secretkey($kp)
    {
        if (self::use_fallback('crypto_box_secretkey')) {
            return call_user_func_array(
                '\\Sodium\\crypto_box_secretkey',
                array($kp)
            );
        }
        return ParagonIE_Sodium_Crypto::box_secretkey($kp);
    }

    /**
     * @param string $ciphertext
     * @param string $nonce
     * @param string $key
     * @return string
     */
    public static function crypto_box_open($ciphertext, $nonce, $key)
    {
        if (self::use_fallback('crypto_box_open')) {
            return call_user_func_array(
                '\\Sodium\\crypto_box_open',
                array($ciphertext, $nonce, $key)
            );
        }
        return ParagonIE_Sodium_Crypto::box_open($ciphertext, $nonce, $key);
    }

    /**
     * @param string $message
     * @param string $key
     * @param int $length
     * @return string
     */
    public static function crypto_generichash($message, $key = '', $length = 32)
    {
        if (self::use_fallback('crypto_generichash')) {
            return call_user_func_array(
                '\\Sodium\\crypto_generichash',
                array($message, $key, $length)
            );
        }
        return ParagonIE_Sodium_Crypto::generichash($message, $key, $length);
    }

    /**
     * @param string $key
     * @param int $length
     * @return string
     */
    public static function crypto_generichash_init($key = '', $length = 32)
    {
        if (self::use_fallback('crypto_generichash_init')) {
            return call_user_func_array(
                '\\Sodium\\crypto_generichash_init',
                array($key, $length)
            );
        }
        return ParagonIE_Sodium_Crypto::generichash_init($key, $length);
    }

    /**
     * @param string& $ctx
     * @param string $message
     * @return void
     */
    public static function crypto_generichash_update(&$ctx, $message)
    {
        if (self::use_fallback('crypto_generichash_update')) {
            $func = '\\Sodium\\crypto_generichash_update';
            $func($ctx, $message);
            return;
        }
        $context = '';
        for ($i = 0; $i < ParagonIE_Sodium_Core_Util::strlen($ctx); ++$i) {
            $context .= $ctx[$i];
        }
        $ctx = ParagonIE_Sodium_Crypto::generichash_update($context, $message);
    }

    /**
     * @param string& $ctx
     * @param int $length
     * @return string
     */
    public static function crypto_generichash_final(&$ctx, $length = 32)
    {
        if (self::use_fallback('crypto_generichash_final')) {
            $func = '\\Sodium\\crypto_generichash_final';
            return $func($ctx, $length);
        }
        $result = ParagonIE_Sodium_Crypto::generichash_final($ctx, $length);
        self::memzero($ctx);
        return $result;
    }

    /**
     * @param string $sk
     * @param string $pk
     * @return string
     */
    public static function crypto_scalarmult($sk, $pk)
    {
        if (self::use_fallback('crypto_scalarmult')) {
            return call_user_func_array(
                '\\Sodium\\crypto_scalarmult',
                array($sk, $pk)
            );
        }
        return ParagonIE_Sodium_Crypto::scalarmult($sk, $pk);
    }

    /**
     * @param $sk
     * @return string
     */
    public static function crypto_scalarmult_base($sk)
    {
        if (self::use_fallback('crypto_scalarmult_base')) {
            return call_user_func_array(
                '\\Sodium\\crypto_scalarmult_base',
                array($sk)
            );
        }
        return ParagonIE_Sodium_Crypto::scalarmult_base($sk);
    }

    /**
     * @param string $plaintext
     * @param string $nonce
     * @param string $key
     * @return string
     */
    public static function crypto_secretbox($plaintext, $nonce, $key)
    {
        if (self::use_fallback('crypto_secretbox')) {
            return call_user_func_array(
                '\\Sodium\\crypto_secretbox',
                array($plaintext, $nonce, $key)
            );
        }
        return ParagonIE_Sodium_Crypto::secretbox($plaintext, $nonce, $key);
    }

    /**
     * @param string $ciphertext
     * @param string $nonce
     * @param string $key
     * @return string
     */
    public static function crypto_secretbox_open($ciphertext, $nonce, $key)
    {
        if (self::use_fallback('crypto_secretbox_open')) {
            return call_user_func_array(
                '\\Sodium\\crypto_secretbox_open',
                array($ciphertext, $nonce, $key)
            );
        }
        return ParagonIE_Sodium_Crypto::secretbox_open($ciphertext, $nonce, $key);
    }

    /**
     * @param int $len
     * @param string $nonce
     * @param string $key
     * @return string
     */
    public static function crypto_stream($len, $nonce, $key)
    {
        if (self::use_fallback('crypto_stream')) {
            return call_user_func_array(
                '\\Sodium\\crypto_stream',
                array($len, $nonce, $key)
            );
        }
        return ParagonIE_Sodium_Core_Xsalsa20::xsalsa20($len, $nonce, $key);
    }

    /**
     * @param string $message
     * @param string $key
     * @return string
     */
    public static function crypto_shorthash($message, $key)
    {
        if (self::use_fallback('crypto_shorthash')) {
            return call_user_func_array(
                '\\Sodium\\crypto_shorthash',
                array($message, $key)
            );
        }
        return ParagonIE_Sodium_Core_SipHash::sipHash24($message, $key);
    }

    /**
     * @param string $message
     * @param string $nonce
     * @param string $key
     * @return string
     */
    public static function crypto_stream_xor($message, $nonce, $key)
    {
        return ParagonIE_Sodium_Core_Xsalsa20::xsalsa20_xor($message, $nonce, $key);
    }

    /**
     * @param string $message
     * @param string $sk
     * @return string
     */
    public static function crypto_sign($message, $sk)
    {
        if (self::use_fallback('crypto_sign_detached')) {
            return call_user_func_array(
                '\\Sodium\\crypto_sign',
                array($message, $sk)
            );
        }
        return ParagonIE_Sodium_Crypto::sign($message, $sk);
    }

    /**
     * @param string $sm
     * @param string $pk
     * @return string
     */
    public static function crypto_sign_open($sm, $pk)
    {
        if (self::use_fallback('crypto_sign_detached')) {
            return call_user_func_array(
                '\\Sodium\\crypto_sign_open',
                array($sm, $pk)
            );
        }
        return ParagonIE_Sodium_Crypto::sign($sm, $pk);
    }

    /**
     * @return string
     */
    public static function crypto_sign_keypair()
    {
        if (self::use_fallback('crypto_sign_keypair')) {
            return call_user_func(
                '\\Sodium\\crypto_sign_keypair'
            );
        }
        return ParagonIE_Sodium_Core_Ed25519::keypair();
    }

    /**
     * @param string $kp
     * @return string
     */
    public static function crypto_sign_publickey($kp)
    {
        if (self::use_fallback('crypto_sign_publickey')) {
            return call_user_func_array(
                '\\Sodium\\crypto_sign_publickey',
                array($kp)
            );
        }
        return ParagonIE_Sodium_Core_Ed25519::publickey($kp);
    }

    /**
     * @param string $kp
     * @return string
     */
    public static function crypto_sign_secretkey($kp)
    {
        return ParagonIE_Sodium_Core_Ed25519::secretkey($kp);
    }

    /**
     * @param string $message
     * @param string $sk
     * @return string
     */
    public static function crypto_sign_detached($message, $sk)
    {
        if (self::use_fallback('crypto_sign_detached')) {
            return call_user_func_array(
                '\\Sodium\\crypto_sign_detached',
                array($message, $sk)
            );
        }
        return ParagonIE_Sodium_Crypto::sign_detached($message, $sk);
    }

    /**
     * @param string $signature
     * @param string $message
     * @param string $pk
     * @return bool
     */
    public static function crypto_sign_verify_detached($signature, $message, $pk)
    {
        if (self::use_fallback('crypto_sign_verify_detached')) {
            return call_user_func_array(
                '\\Sodium\\crypto_sign_verify_detached',
                array($signature, $message, $pk)
            );
        }
        return ParagonIE_Sodium_Crypto::sign_verify_detached($signature, $message, $pk);
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
