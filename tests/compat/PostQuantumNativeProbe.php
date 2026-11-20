<?php

class PostQuantumNativeProbe extends ParagonIE_Sodium_Compat
{
    public static function native($function)
    {
        return self::useNewSodiumAPI($function);
    }
}
