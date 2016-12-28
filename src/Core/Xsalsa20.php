<?php

/**
 * Class ParagonIE_Sodium_Core_XSalsa20
 */
abstract class ParagonIE_Sodium_Core_XSalsa20 extends ParagonIE_Sodium_Core_HSalsa20
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
        $ret = self::salsa20($len, self::substr($nonce, 16, 8), $subkey);
        ParagonIE_Sodium_Compat::memzero($subkey);
        return $ret;
    }

    /**
     * @param string $message
     * @param string $nonce
     * @param string $key
     * @return string
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
