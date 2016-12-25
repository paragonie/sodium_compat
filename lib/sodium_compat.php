<?php
namespace Sodium;

/* If the PHP extension is installed, don't do anything
 */
if (!extension_loaded('libsodium')) {
    if (!is_callable('\\Sodium\\bin2hex')) {
        /**
         * @param $string
         * @return string
         */
        function bin2hex($string)
        {
            return call_user_func_array(
                array('ParagonIE_Sodium_Compat', 'bin2hex'),
                array($string)
            );
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
            return call_user_func_array(
                array('ParagonIE_Sodium_Compat', 'compare'),
                array($a, $b)
            );
        }
    }
    if (!is_callable('\\Sodium\\compare')) {
        /**
         * @param string $a
         * @param string $b
         * @return int
         */
        function memcmp($a, $b)
        {
            return call_user_func_array(
                array('ParagonIE_Sodium_Compat', 'memcmp'),
                array($a, $b)
            );
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
            return call_user_func_array(
                array('ParagonIE_Sodium_Compat', 'crypto_sign_detached'),
                array($message, $sk)
            );
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
            return call_user_func_array(
                array('ParagonIE_Sodium_Compat', 'crypto_sign'),
                array($message, $sk)
            );
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
            return call_user_func_array(
                array('ParagonIE_Sodium_Compat', 'crypto_sign_open'),
                array($signedMessage, $pk)
            );
        }
    }
    if (!is_callable('\\Sodium\\crypto_sign_publickey')) {
        /**
         * @param string $keypair
         * @return string
         */
        function crypto_sign_publickey($keypair)
        {
            return call_user_func_array(
                array('ParagonIE_Sodium_Compat', 'crypto_sign_publickey'),
                array($keypair)
            );
        }
    }
    if (!is_callable('\\Sodium\\crypto_sign_publickey_from_secretkey')) {
        /**
         * @param string $sk
         * @return string
         */
        function crypto_sign_publickey_from_secretkey($sk)
        {
            return call_user_func_array(
                array('ParagonIE_Sodium_Compat', 'crypto_sign_publickey_from_secretkey'),
                array($sk)
            );
        }
    }
    if (!is_callable('\\Sodium\\crypto_sign_secretkey')) {
        /**
         * @param string $keypair
         * @return string
         */
        function crypto_sign_secretkey($keypair)
        {
            return call_user_func_array(
                array('ParagonIE_Sodium_Compat', 'crypto_sign_secretkey'),
                array($keypair)
            );
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
            return call_user_func_array(
                array('ParagonIE_Sodium_Compat', 'crypto_sign_verify_detached'),
                array($signature, $message, $pk)
            );
        }
    }
    if (!is_callable('\\Sodium\\hex2bin')) {
        /**
         * @param $string
         * @return string
         */
        function hex2bin($string)
        {
            return call_user_func_array(
                array('ParagonIE_Sodium_Compat', 'hex2bin'),
                array($string)
            );
        }
    }
    if (!is_callable('\\Sodium\\randombytes_buf')) {
        /**
         * @param int $amount
         * @return string
         */
        function randombytes_buf($amount)
        {
            return call_user_func_array(
                array('ParagonIE_Sodium_Compat', 'randombytes_buf'),
                array($amount)
            );
        }
    }

    if (!is_callable('\\Sodium\\randombytes_uniform')) {
        /**
         * @param int $upperLimit
         * @return int
         */
        function randombytes_uniform($upperLimit)
        {
            return call_user_func_array(
                array('ParagonIE_Sodium_Compat', 'randombytes_uniform'),
                array($upperLimit)
            );
        }
    }

    if (!is_callable('\\Sodium\\randombytes_uniform')) {
        /**
         * @return int
         */
        function randombytes_random16()
        {
            return call_user_func(
                array('ParagonIE_Sodium_Compat', 'randombytes_random16')
            );
        }
    }
}
