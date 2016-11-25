<?php

/**
 * Class ParagonIE_Sodium_Core_Curve25519_Ge_Cached
 */
class ParagonIE_Sodium_Core_Curve25519_Ge_Cached
{
    /**
     * @var ParagonIE_Sodium_Core_Curve25519_Fe
     */
    public $YplusX;

    /**
     * @var ParagonIE_Sodium_Core_Curve25519_Fe
     */
    public $YminusX;

    /**
     * @var ParagonIE_Sodium_Core_Curve25519_Fe
     */
    public $Z;

    /**
     * @var ParagonIE_Sodium_Core_Curve25519_Fe
     */
    public $T2d;

    /**
     * ParagonIE_Sodium_Core_Curve25519_Ge_Cached constructor.
     * @param ParagonIE_Sodium_Core_Curve25519_Fe|null $YplusX
     * @param ParagonIE_Sodium_Core_Curve25519_Fe|null $YminusX
     * @param ParagonIE_Sodium_Core_Curve25519_Fe|null $Z
     * @param ParagonIE_Sodium_Core_Curve25519_Fe|null $T2d
     */
    public function __construct(
        ParagonIE_Sodium_Core_Curve25519_Fe $YplusX = null,
        ParagonIE_Sodium_Core_Curve25519_Fe $YminusX = null,
        ParagonIE_Sodium_Core_Curve25519_Fe $Z = null,
        ParagonIE_Sodium_Core_Curve25519_Fe $T2d = null
    ) {
        $this->YplusX = $YplusX;
        $this->YminusX = $YminusX;
        $this->Z = $Z;
        $this->T2d = $T2d;
    }
}