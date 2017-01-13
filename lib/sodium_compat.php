<?php
namespace Sodium;

use ParagonIE_Sodium_Compat;

/**
 * This file will monkey patch the pure-PHP implementation in place of the
 * PECL functions, but only if they do not already exist.
 *
 * Thus, the functions just proxy to the appropriate ParagonIE_Sodium_Compat
 * method.
 */
if (!is_callable('\\Sodium\\bin2hex')) {
    /**
     * @param $string
     * @return string
     */
    function bin2hex($string)
    {
        return ParagonIE_Sodium_Compat::bin2hex($string);
    }
}
if (!is_callable('\\Sodium\\compare')) {
    /**
     * @param string $a
     * @param string $b
     * @return int
     */
    function compare($a, $b)
    {
        return ParagonIE_Sodium_Compat::compare($a, $b);
    }
}
if (!is_callable('\\Sodium\\crypto_auth')) {
    /**
     * @param string $message
     * @param string $key
     * @return string
     */
    function crypto_auth($message, $key)
    {
        return ParagonIE_Sodium_Compat::crypto_auth($message, $key);
    }
}
if (!is_callable('\\Sodium\\crypto_auth_verify')) {
    /**
     * @param string $mac
     * @param string $message
     * @param string $key
     * @return bool
     */
    function crypto_auth_verify($mac, $message, $key)
    {
        return ParagonIE_Sodium_Compat::crypto_auth_verify($mac, $message, $key);
    }
}
if (!is_callable('\\Sodium\\crypto_box')) {
    /**
     * @param string $message
     * @param string $nonce
     * @param string $kp
     * @return string
     */
    function crypto_box($message, $nonce, $kp)
    {
        return ParagonIE_Sodium_Compat::crypto_box($message, $nonce, $kp);
    }
}
if (!is_callable('\\Sodium\\crypto_box_keypair')) {
    /**
     * @return string
     */
    function crypto_box_keypair()
    {
        return ParagonIE_Sodium_Compat::crypto_box_keypair();
    }
}
if (!is_callable('\\Sodium\\crypto_box_keypair_from_secretkey_and_publickey')) {
    /**
     * @param string $sk
     * @param string $pk
     * @return string
     */
    function crypto_box_keypair_from_secretkey_and_publickey($sk, $pk)
    {
        return ParagonIE_Sodium_Compat::crypto_box_keypair_from_secretkey_and_publickey($sk, $pk);
    }
}
if (!is_callable('\\Sodium\\crypto_box_open')) {
    /**
     * @param string $message
     * @param string $nonce
     * @param string $kp
     * @return string
     */
    function crypto_box_open($message, $nonce, $kp)
    {
        return ParagonIE_Sodium_Compat::crypto_box_open($message, $nonce, $kp);
    }
}
if (!is_callable('\\Sodium\\crypto_box_publickey')) {
    /**
     * @param string $keypair
     * @return string
     */
    function crypto_box_publickey($keypair)
    {
        return ParagonIE_Sodium_Compat::crypto_box_publickey($keypair);
    }
}
if (!is_callable('\\Sodium\\crypto_box_publickey_from_secretkey')) {
    /**
     * @param string $sk
     * @return string
     */
    function crypto_box_publickey_from_secretkey($sk)
    {
        return ParagonIE_Sodium_Compat::crypto_box_publickey_from_secretkey($sk);
    }
}
if (!is_callable('\\Sodium\\crypto_box_seal')) {
    /**
     * @param string $message
     * @param string $publicKey
     * @return string
     */
    function crypto_box_seal($message, $publicKey)
    {
        return ParagonIE_Sodium_Compat::crypto_box_seal($message, $publicKey);
    }
}
if (!is_callable('\\Sodium\\crypto_box_seal_open')) {
    /**
     * @param string $message
     * @param string $kp
     * @return string
     */
    function crypto_box_seal_open($message, $kp)
    {
        return ParagonIE_Sodium_Compat::crypto_box_seal_open($message, $kp);
    }
}
if (!is_callable('\\Sodium\\crypto_box_secretkey')) {
    /**
     * @param string $keypair
     * @return string
     */
    function crypto_box_secretkey($keypair)
    {
        return ParagonIE_Sodium_Compat::crypto_box_secretkey($keypair);
    }
}
if (!is_callable('\\Sodium\\crypto_generichash')) {
    /**
     * @param string $message
     * @param string|null $key
     * @param int $outLen
     * @return string
     */
    function crypto_generichash($message, $key = null, $outLen = 32)
    {
        return ParagonIE_Sodium_Compat::crypto_generichash($message, $key, $outLen);
    }
}
if (!is_callable('\\Sodium\\crypto_generichash_final')) {
    /**
     * @param string|null $ctx
     * @param int $outputLength
     * @return string
     */
    function crypto_generichash_final(&$ctx, $outputLength = 32)
    {
        return ParagonIE_Sodium_Compat::crypto_generichash_final($ctx, $outputLength);
    }
}
if (!is_callable('\\Sodium\\crypto_generichash_init')) {
    /**
     * @param string|null $key
     * @param int $outLen
     * @return string
     */
    function crypto_generichash_init($key = null, $outLen = 32)
    {
        return ParagonIE_Sodium_Compat::crypto_generichash_init($key, $outLen);
    }
}
if (!is_callable('\\Sodium\\crypto_generichash_update')) {
    /**
     * @param string|null $ctx
     * @param string $message
     * @return void
     */
    function crypto_generichash_update(&$ctx, $message = '')
    {
        ParagonIE_Sodium_Compat::crypto_generichash_update($ctx, $message);
    }
}
if (!is_callable('\\Sodium\\crypto_kx')) {
    /**
     * @param string $my_secret
     * @param string $their_public
     * @param string $client_public
     * @param string $server_public
     * @return string
     */
    function crypto_kx($my_secret, $their_public, $client_public, $server_public)
    {
        return ParagonIE_Sodium_Compat::crypto_kx(
            $my_secret,
            $their_public,
            $client_public,
            $server_public
        );
    }
}
if (!is_callable('\\Sodium\\crypto_scalarmult')) {
    /**
     * @param string $n
     * @param string $p
     * @return string
     */
    function crypto_scalarmult($n, $p)
    {
        return ParagonIE_Sodium_Compat::crypto_scalarmult($n, $p);
    }
}
if (!is_callable('\\Sodium\\crypto_secretbox')) {
    /**
     * @param string $message
     * @param string $nonce
     * @param string $key
     * @return string
     */
    function crypto_secretbox($message, $nonce, $key)
    {
        return ParagonIE_Sodium_Compat::crypto_secretbox($message, $nonce, $key);
    }
}
if (!is_callable('\\Sodium\\crypto_secretbox_open')) {
    /**
     * @param string $message
     * @param string $nonce
     * @param string $key
     * @return string
     */
    function crypto_secretbox_open($message, $nonce, $key)
    {
        return ParagonIE_Sodium_Compat::crypto_secretbox_open($message, $nonce, $key);
    }
}
if (!is_callable('\\Sodium\\crypto_shorthash')) {
    /**
     * @param string $message
     * @param string $key
     * @return string
     */
    function crypto_shorthash($message, $key = '')
    {
        return ParagonIE_Sodium_Compat::crypto_shorthash($message, $key);
    }
}
if (!is_callable('\\Sodium\\crypto_sign')) {
    /**
     * @param string $message
     * @param string $sk
     * @return string
     */
    function crypto_sign($message, $sk)
    {
        return ParagonIE_Sodium_Compat::crypto_sign($message, $sk);
    }
}
if (!is_callable('\\Sodium\\crypto_sign_detached')) {
    /**
     * @param string $message
     * @param string $sk
     * @return string
     */
    function crypto_sign_detached($message, $sk)
    {
        return ParagonIE_Sodium_Compat::crypto_sign_detached($message, $sk);
    }
}
if (!is_callable('\\Sodium\\crypto_sign_keypair')) {
    /**
     * @return string
     */
    function crypto_sign_keypair()
    {
        return ParagonIE_Sodium_Compat::crypto_sign_keypair();
    }
}
if (!is_callable('\\Sodium\\crypto_sign_open')) {
    /**
     * @param string $signedMessage
     * @param string $pk
     * @return string
     */
    function crypto_sign_open($signedMessage, $pk)
    {
        return ParagonIE_Sodium_Compat::crypto_sign_open($signedMessage, $pk);
    }
}
if (!is_callable('\\Sodium\\crypto_sign_publickey')) {
    /**
     * @param string $keypair
     * @return string
     */
    function crypto_sign_publickey($keypair)
    {
        return ParagonIE_Sodium_Compat::crypto_sign_publickey($keypair);
    }
}
if (!is_callable('\\Sodium\\crypto_sign_publickey_from_secretkey')) {
    /**
     * @param string $sk
     * @return string
     */
    function crypto_sign_publickey_from_secretkey($sk)
    {
        return ParagonIE_Sodium_Compat::crypto_sign_publickey_from_secretkey($sk);
    }
}
if (!is_callable('\\Sodium\\crypto_sign_secretkey')) {
    /**
     * @param string $keypair
     * @return string
     */
    function crypto_sign_secretkey($keypair)
    {
        return ParagonIE_Sodium_Compat::crypto_sign_secretkey($keypair);
    }
}
if (!is_callable('\\Sodium\\crypto_sign_verify_detached')) {
    /**
     * @param string $signature
     * @param string $message
     * @param string $pk
     * @return bool
     */
    function crypto_sign_verify_detached($signature, $message, $pk)
    {
        return ParagonIE_Sodium_Compat::crypto_sign_verify_detached($signature, $message, $pk);
    }
}
if (!is_callable('\\Sodium\\crypto_stream')) {
    /**
     * @param int $len
     * @param string $nonce
     * @param string $key
     * @return string
     */
    function crypto_stream($len, $nonce, $key)
    {
        return ParagonIE_Sodium_Compat::crypto_stream($len, $nonce, $key);
    }
}
if (!is_callable('\\Sodium\\crypto_stream_xor')) {
    /**
     * @param $message
     * @param $nonce
     * @param $key
     * @return mixed
     */
    function crypto_stream_xor($message, $nonce, $key)
    {
        return ParagonIE_Sodium_Compat::crypto_stream_xor($message, $nonce, $key);
    }
}
if (!is_callable('\\Sodium\\hex2bin')) {
    /**
     * @param $string
     * @return string
     */
    function hex2bin($string)
    {
        return ParagonIE_Sodium_Compat::hex2bin($string);
    }
}
if (!is_callable('\\Sodium\\memcmp')) {
    /**
     * @param string $a
     * @param string $b
     * @return int
     */
    function memcmp($a, $b)
    {
        return ParagonIE_Sodium_Compat::memcmp($a, $b);
    }
}
if (!is_callable('\\Sodium\\randombytes_buf')) {
    /**
     * @param int $amount
     * @return string
     */
    function randombytes_buf($amount)
    {
        return ParagonIE_Sodium_Compat::randombytes_buf($amount);
    }
}

if (!is_callable('\\Sodium\\randombytes_uniform')) {
    /**
     * @param int $upperLimit
     * @return int
     */
    function randombytes_uniform($upperLimit)
    {
        return ParagonIE_Sodium_Compat::randombytes_uniform($upperLimit);
    }
}

if (!is_callable('\\Sodium\\randombytes_random16')) {
    /**
     * @return int
     */
    function randombytes_random16()
    {
        return ParagonIE_Sodium_Compat::randombytes_random16();
    }
}

if (!defined('\\Sodium\\CRYPTO_AUTH_BYTES')) {
    define('\\Sodium\\CRYPTO_AUTH_BYTES', ParagonIE_Sodium_Compat::CRYPTO_AUTH_BYTES);
}
if (!defined('\\Sodium\\CRYPTO_AUTH_KEYBYTES')) {
    define('\\Sodium\\CRYPTO_AUTH_KEYBYTES', ParagonIE_Sodium_Compat::CRYPTO_AUTH_KEYBYTES);
}
if (!defined('\\Sodium\\CRYPTO_BOX_SEALBYTES')) {
    define('\\Sodium\\CRYPTO_BOX_SEALBYTES', ParagonIE_Sodium_Compat::CRYPTO_BOX_SEALBYTES);
}
if (!defined('\\Sodium\\CRYPTO_BOX_SECRETKEYBYTES')) {
    define('\\Sodium\\CRYPTO_BOX_SECRETKEYBYTES', ParagonIE_Sodium_Compat::CRYPTO_BOX_SECRETKEYBYTES);
}
if (!defined('\\Sodium\\CRYPTO_BOX_PUBLICKEYBYTES')) {
    define('\\Sodium\\CRYPTO_BOX_PUBLICKEYBYTES', ParagonIE_Sodium_Compat::CRYPTO_BOX_PUBLICKEYBYTES);
}
if (!defined('\\Sodium\\CRYPTO_BOX_KEYPAIRBYTES')) {
    define('\\Sodium\\CRYPTO_BOX_KEYPAIRBYTES', ParagonIE_Sodium_Compat::CRYPTO_BOX_KEYPAIRBYTES);
}
if (!defined('\\Sodium\\CRYPTO_BOX_MACBYTES')) {
    define('\\Sodium\\CRYPTO_BOX_MACBYTES', ParagonIE_Sodium_Compat::CRYPTO_BOX_MACBYTES);
}
if (!defined('\\Sodium\\CRYPTO_BOX_NONCEBYTES')) {
    define('\\Sodium\\CRYPTO_BOX_NONCEBYTES', ParagonIE_Sodium_Compat::CRYPTO_BOX_NONCEBYTES);
}
if (!defined('\\Sodium\\CRYPTO_BOX_SEEDBYTES')) {
    define('\\Sodium\\CRYPTO_BOX_SEEDBYTES', ParagonIE_Sodium_Compat::CRYPTO_BOX_SEEDBYTES);
}
if (!defined('\\Sodium\\CRYPTO_KX_BYTES')) {
    define('\\Sodium\\CRYPTO_KX_BYTES', ParagonIE_Sodium_Compat::CRYPTO_KX_BYTES);
}
if (!defined('\\Sodium\\CRYPTO_KX_PUBLICKEYBYTES')) {
    define('\\Sodium\\CRYPTO_KX_PUBLICKEYBYTES', ParagonIE_Sodium_Compat::CRYPTO_KX_PUBLICKEYBYTES);
}
if (!defined('\\Sodium\\CRYPTO_KX_SECRETKEYBYTES')) {
    define('\\Sodium\\CRYPTO_KX_SECRETKEYBYTES', ParagonIE_Sodium_Compat::CRYPTO_KX_SECRETKEYBYTES);
}
if (!defined('\\Sodium\\CRYPTO_GENERICHASH_BYTES')) {
    define('\\Sodium\\CRYPTO_GENERICHASH_BYTES', ParagonIE_Sodium_Compat::CRYPTO_GENERICHASH_BYTES);
}
if (!defined('\\Sodium\\CRYPTO_GENERICHASH_BYTES_MIN')) {
    define('\\Sodium\\CRYPTO_GENERICHASH_BYTES_MIN', ParagonIE_Sodium_Compat::CRYPTO_GENERICHASH_BYTES_MIN);
}
if (!defined('\\Sodium\\CRYPTO_GENERICHASH_BYTES_MAX')) {
    define('\\Sodium\\CRYPTO_GENERICHASH_BYTES_MAX', ParagonIE_Sodium_Compat::CRYPTO_GENERICHASH_BYTES_MAX);
}
if (!defined('\\Sodium\\CRYPTO_GENERICHASH_KEYBYTES')) {
    define('\\Sodium\\CRYPTO_GENERICHASH_KEYBYTES', ParagonIE_Sodium_Compat::CRYPTO_GENERICHASH_KEYBYTES);
}
if (!defined('\\Sodium\\CRYPTO_GENERICHASH_KEYBYTES_MIN')) {
    define('\\Sodium\\CRYPTO_GENERICHASH_KEYBYTES_MIN', ParagonIE_Sodium_Compat::CRYPTO_GENERICHASH_KEYBYTES_MIN);
}
if (!defined('\\Sodium\\CRYPTO_GENERICHASH_KEYBYTES_MAX')) {
    define('\\Sodium\\CRYPTO_GENERICHASH_KEYBYTES_MAX', ParagonIE_Sodium_Compat::CRYPTO_GENERICHASH_KEYBYTES_MAX);
}
if (!defined('\\Sodium\\CRYPTO_SCALARMULT_BYTES')) {
    define('\\Sodium\\CRYPTO_SCALARMULT_BYTES', ParagonIE_Sodium_Compat::CRYPTO_SCALARMULT_BYTES);
}
if (!defined('\\Sodium\\CRYPTO_SCALARMULT_SCALARBYTES')) {
    define('\\Sodium\\CRYPTO_SCALARMULT_SCALARBYTES', ParagonIE_Sodium_Compat::CRYPTO_SCALARMULT_SCALARBYTES);
}
if (!defined('\\Sodium\\CRYPTO_SHORTHASH_BYTES')) {
    define('\\Sodium\\CRYPTO_SHORTHASH_BYTES', ParagonIE_Sodium_Compat::CRYPTO_SHORTHASH_BYTES);
}
if (!defined('\\Sodium\\CRYPTO_SHORTHASH_KEYBYTES')) {
    define('\\Sodium\\CRYPTO_SHORTHASH_KEYBYTES', ParagonIE_Sodium_Compat::CRYPTO_SHORTHASH_KEYBYTES);
}
if (!defined('\\Sodium\\CRYPTO_SECRETBOX_KEYBYTES')) {
    define('\\Sodium\\CRYPTO_SECRETBOX_KEYBYTES', ParagonIE_Sodium_Compat::CRYPTO_SECRETBOX_KEYBYTES);
}
if (!defined('\\Sodium\\CRYPTO_SECRETBOX_MACBYTES')) {
    define('\\Sodium\\CRYPTO_SECRETBOX_MACBYTES', ParagonIE_Sodium_Compat::CRYPTO_SECRETBOX_MACBYTES);
}
if (!defined('\\Sodium\\CRYPTO_SECRETBOX_NONCEBYTES')) {
    define('\\Sodium\\CRYPTO_SECRETBOX_NONCEBYTES', ParagonIE_Sodium_Compat::CRYPTO_SECRETBOX_NONCEBYTES);
}
if (!defined('\\Sodium\\CRYPTO_SIGN_BYTES')) {
    define('\\Sodium\\CRYPTO_SIGN_BYTES', ParagonIE_Sodium_Compat::CRYPTO_SIGN_BYTES);
}
if (!defined('\\Sodium\\CRYPTO_SIGN_SEEDBYTES')) {
    define('\\Sodium\\CRYPTO_SIGN_SEEDBYTES', ParagonIE_Sodium_Compat::CRYPTO_SIGN_SEEDBYTES);
}
if (!defined('\\Sodium\\CRYPTO_SIGN_PUBLICKEYBYTES')) {
    define('\\Sodium\\CRYPTO_SIGN_PUBLICKEYBYTES', ParagonIE_Sodium_Compat::CRYPTO_SIGN_PUBLICKEYBYTES);
}
if (!defined('\\Sodium\\CRYPTO_SIGN_SECRETKEYBYTES')) {
    define('\\Sodium\\CRYPTO_SIGN_SECRETKEYBYTES', ParagonIE_Sodium_Compat::CRYPTO_SIGN_SECRETKEYBYTES);
}
if (!defined('\\Sodium\\CRYPTO_SIGN_KEYPAIRBYTES')) {
    define('\\Sodium\\CRYPTO_SIGN_KEYPAIRBYTES', ParagonIE_Sodium_Compat::CRYPTO_SIGN_KEYPAIRBYTES);
}
if (!defined('\\Sodium\\CRYPTO_STREAM_KEYBYTES')) {
    define('\\Sodium\\CRYPTO_STREAM_KEYBYTES', ParagonIE_Sodium_Compat::CRYPTO_STREAM_KEYBYTES);
}
if (!defined('\\Sodium\\CRYPTO_STREAM_NONCEBYTES')) {
    define('\\Sodium\\CRYPTO_STREAM_NONCEBYTES', ParagonIE_Sodium_Compat::CRYPTO_STREAM_NONCEBYTES);
}
