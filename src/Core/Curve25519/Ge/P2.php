<?php

/**
 * Class ParagonIE_Sodium_Core_Curve25519_Ge_P2
 */
class ParagonIE_Sodium_Core_Curve25519_Ge_P2
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
     * ParagonIE_Sodium_Core_Curve25519_Ge_P2 constructor.
     * @param ParagonIE_Sodium_Core_Curve25519_Fe $x
     * @param ParagonIE_Sodium_Core_Curve25519_Fe $y
     * @param ParagonIE_Sodium_Core_Curve25519_Fe $z
     */
    public function __construct(
        ParagonIE_Sodium_Core_Curve25519_Fe $x = null,
        ParagonIE_Sodium_Core_Curve25519_Fe $y = null,
        ParagonIE_Sodium_Core_Curve25519_Fe $z = null
    ) {
        $this->X = $x;
        $this->Y = $y;
        $this->Z = $z;
    }
}
