<?php

/**
 * Class ParagonIE_Sodium_Core_Curve25519_Ge_P3
 */
class ParagonIE_Sodium_Core_Curve25519_Ge_P3
{
    /**
     * @var ParagonIE_Sodium_Core_Curve25519_Fe
     */
    public $X;

    /**
     * @var ParagonIE_Sodium_Core_Curve25519_Fe
     */
    public $Y;

    /**
     * @var ParagonIE_Sodium_Core_Curve25519_Fe
     */
    public $Z;

    /**
     * @var ParagonIE_Sodium_Core_Curve25519_Fe
     */
    public $T;

    public function __construct(
        ParagonIE_Sodium_Core_Curve25519_Fe $x = null,
        ParagonIE_Sodium_Core_Curve25519_Fe $y = null,
        ParagonIE_Sodium_Core_Curve25519_Fe $z = null,
        ParagonIE_Sodium_Core_Curve25519_Fe $t = null
    ) {
        $this->X = $x;
        $this->Y = $y;
        $this->Z = $z;
        $this->T = $t;
    }
}
