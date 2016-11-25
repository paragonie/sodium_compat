<?php

class ParagonIE_Sodium_Core_XSalsa20 extends ParagonIE_Sodium_Core_HSalsa20
{
    /**
     * @param string $len
     * @param string $nonce
     * @param string $key
     * @return string;
     */
    public static function xsalsa20($len, $nonce, $key)
    {
        $subkey = self::hsalsa20($nonce, $key);
        $ret = self::salsa20($len, $nonce, $subkey);
        ParagonIE_Sodium_Compat::memzero(&$subkey);
        return $ret;
    }

    /**
     * @param $message
     * @param $nonce
     * @param $key
     */
    public static function xsalsa20_xor($message, $nonce, $key)
    {
        return self::xorStrings(
            $message,
            self::xsalsa20(
                self::strlen($message),
                $nonce,
                $key
            )
        );
    }
}
