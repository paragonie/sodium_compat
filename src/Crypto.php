<?php

class ParagonIE_Sodium_Crypto
{
    /**
     * @param string $message
     * @param string $key
     * @return string
     */
    public static function auth($message, $key)
    {

    }

    /**
     * @param string $mac
     * @param string $message
     * @param string $key
     * @return bool
     */
    public static function auth_verify($mac, $message, $key)
    {
        return hash_equals(
            $mac,
            self::auth($message, $key)
        );
    }

    /**
     * @param string $plaintext
     * @param string $nonce
     * @param string $keypair
     */
    public function box($plaintext, $nonce, $keypair)
    {

    }

    /**
     * @param string $ciphertext
     * @param string $nonce
     * @param string $keypair
     */
    public function box_open($ciphertext, $nonce, $keypair)
    {

    }

    /**
     * @param string $plaintext
     * @param string $nonce
     * @param string $key
     * @return string
     */
    public static function secretbox($plaintext, $nonce, $key)
    {

    }

    /**
     * @param string $ciphertext
     * @param string $nonce
     * @param string $key
     * @return string
     */
    public static function secretbox_open($ciphertext, $nonce, $key)
    {

    }

    /**
     * @param string $message
     * @param string $sk
     */
    public static function sign_detached($message, $sk)
    {

    }

    /**
     * @param string $signature
     * @param string $message
     * @param string $pk
     */
    public static function sign_verify_detached($signature, $message, $pk)
    {

    }
}
