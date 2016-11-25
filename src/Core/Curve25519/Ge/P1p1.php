<?php

/**
 * Class ParagonIE_Sodium_Core_Curve25519_Ge_P1p1
 */
class ParagonIE_Sodium_Core_Curve25519_Ge_P1p1
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

    /**
     * ParagonIE_Sodium_Core_Curve25519_Ge_P1p1 constructor.
     * @param ParagonIE_Sodium_Core_Curve25519_Fe $x
     * @param ParagonIE_Sodium_Core_Curve25519_Fe $y
     * @param ParagonIE_Sodium_Core_Curve25519_Fe $z
     * @param ParagonIE_Sodium_Core_Curve25519_Fe $t
     */
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
