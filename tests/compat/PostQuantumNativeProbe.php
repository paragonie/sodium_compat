<?php

class PostQuantumNativeProbe extends ParagonIE_Sodium_Compat
{
    public static function native(string $function): bool
    {
        return self::usePQNative($function);
    }
}
