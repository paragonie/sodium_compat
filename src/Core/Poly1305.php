<?php

/**
 * Class ParagonIE_Sodium_Core_Poly1305
 */
abstract class ParagonIE_Sodium_Core_Poly1305 extends ParagonIE_Sodium_Core_Util
{
    const BLOCK_SIZE = 16;

    /**
     * @param string $m
     * @param string $key
     * @return string
     */
    public static function onetimeauth($m, $key)
    {
        $state = new ParagonIE_Sodium_Core_Poly1305_State($key);
        return $state->update($m)->finish();
    }

    /**
     * @param string $mac
     * @param string $m
     * @param string $key
     * @return bool
     */
    public static function onetimeauth_verify($mac, $m, $key)
    {
        $state = new ParagonIE_Sodium_Core_Poly1305_State($key);
        $calc = $state->update($m)->finish();
        return self::verify_16($calc, $mac);
    }
}
