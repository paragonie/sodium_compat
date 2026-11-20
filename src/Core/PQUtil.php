<?php

/** @internal Byte utilities for the post-quantum primitives. */
class ParagonIE_Sodium_Core_PQUtil extends ParagonIE_Sodium_Core_Util
{
    /**
     * @throws SodiumException
     */
    public static function assertLength(#[SensitiveParameter] string $value, int $length): void
    {
        if (self::strlen($value) !== $length) {
            throw new SodiumException('Expected ' . $length . ' bytes');
        }
    }
}
