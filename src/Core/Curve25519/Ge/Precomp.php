<?php

/**
 * Class ParagonIE_Sodium_Core_Curve25519_Ge_Precomp
 */
class ParagonIE_Sodium_Core_Curve25519_Ge_Precomp
{
    /**
     * @var ParagonIE_Sodium_Core_Curve25519_Fe
     */
    public $yplusx;

    /**
     * @var ParagonIE_Sodium_Core_Curve25519_Fe
     */
    public $yminusx;

    /**
     * @var ParagonIE_Sodium_Core_Curve25519_Fe
     */
    public $xy2d;

    /**
     * ParagonIE_Sodium_Core_Curve25519_Ge_Precomp constructor.
     * @param ParagonIE_Sodium_Core_Curve25519_Fe $yplusx
     * @param ParagonIE_Sodium_Core_Curve25519_Fe $yminusx
     * @param ParagonIE_Sodium_Core_Curve25519_Fe $xy2d
     */
    public function __construct(
        ParagonIE_Sodium_Core_Curve25519_Fe $yplusx = null,
        ParagonIE_Sodium_Core_Curve25519_Fe $yminusx = null,
        ParagonIE_Sodium_Core_Curve25519_Fe $xy2d = null
    ) {
        $this->yplusx = $yplusx;
        $this->yminusx = $yminusx;
        $this->xy2d = $xy2d;
    }

}