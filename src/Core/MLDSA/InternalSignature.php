<?php

/**
 * @internal
 * @psalm-suppress PossiblyUnusedMethod
 */
final class ParagonIE_Sodium_Core_MLDSA_InternalSignature
{
    /**
     * @param ParagonIE_Sodium_Core_MLDSA_Params $params
     * @param string $c_tilde
     * @param ParagonIE_Sodium_Core_MLDSA_Ring[] $z
     * @param ParagonIE_Sodium_Core_MLDSA_Ring[] $h
     */
    public function __construct(
        public ParagonIE_Sodium_Core_MLDSA_Params $params,
        public string $c_tilde,
        public array $z,
        public array $h
    ) {}

    /**
     * FIPS 204, Algorithm 26
     */
    public function bytes(): string
    {
        $sig = $this->c_tilde;
        $logGamma1 = $this->params->logGamma1();
        $l = $this->params->l();
        for ($i = 0; $i < $l; ++$i) {
            $packed = ParagonIE_Sodium_Core_MLDSA_Operations::bitPack(
                $this->z[$i]->symmetric(),
                $logGamma1
            );
            $sig .= ParagonIE_Sodium_Core_PQUtil::intArrayToString($packed);
        }
        $packed = ParagonIE_Sodium_Core_MLDSA_Operations::hintBitPack($this->params, $this->h);
        $sig .= ParagonIE_Sodium_Core_PQUtil::intArrayToString($packed);
        return $sig;
    }

    /**
     * FIPS 204, Algorithm 27
     *
     * @throws SodiumException
     */
    public static function fromBytes(ParagonIE_Sodium_Core_MLDSA_Params $params, string $encoded): self
    {
        if (strlen($encoded) !== $params->signatureSize()) {
            throw new SodiumException('Invalid signature length');
        }
        $sig = $encoded;
        $logGamma1 = $params->logGamma1();
        $l = $params->l();
        $lambda_4 = $params->lambda() >> 2;
        $c_tilde = substr($sig, 0, $lambda_4);
        $sig = substr($sig, $lambda_4);
        $len = ($logGamma1 + 1) << 5;
        $z = [];
        for ($i = 0; $i < $l; ++$i) {
            $x_i = ParagonIE_Sodium_Core_PQUtil::stringtoIntArray(substr($sig, 0, $len));
            $sig = substr($sig, $len);
            $z[$i] = ParagonIE_Sodium_Core_MLDSA_Operations::bitUnpack($x_i, $logGamma1);
        }
        $h = ParagonIE_Sodium_Core_MLDSA_Operations::hintBitUnpack(
            $params,
            ParagonIE_Sodium_Core_PQUtil::stringtoIntArray($sig)
        );
        return new self($params, $c_tilde, $z, $h);
    }
}
