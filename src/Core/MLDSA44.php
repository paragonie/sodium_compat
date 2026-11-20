<?php

/** @internal ML-DSA-44 with FIPS 204 expanded signing keys. */
final class ParagonIE_Sodium_Core_MLDSA44 extends ParagonIE_Sodium_Core_PQUtil
{
    /**
     * @throws SodiumException
     */
    public static function seedKeypair(#[SensitiveParameter] string $seed): string
    {
        self::assertLength($seed, 32);
        $params = new ParagonIE_Sodium_Core_MLDSA_Params();
        $key = ParagonIE_Sodium_Core_MLDSA_InternalSigningKey::keyGenInternal($params, $seed);
        $secret = $key->rho . $key->K . $key->tr;
        foreach ([$key->s1hat, $key->s2hat, $key->t0hat] as $i => $vector) {
            foreach (ParagonIE_Sodium_Core_MLDSA_Operations::invNttVec($vector) as $poly) {
                if ($i === 2) {
                    $packed = ParagonIE_Sodium_Core_MLDSA_Operations::bitPack($poly->symmetric(), 12);
                } else {
                    $symmetric = $poly->symmetric();
                    $encoded = new ParagonIE_Sodium_Core_MLDSA_Ring();
                    for ($j = 0; $j < 256; ++$j) {
                        $encoded[$j] = 2 - $symmetric[$j];
                    }
                    $packed = ParagonIE_Sodium_Core_MLDSA_Operations::simpleBitPack($encoded, 3);
                }
                $secret .= self::intArrayToString($packed);
            }
        }
        return $secret . $key->vk->bytes();
    }

    /**
     * @throws SodiumException
     */
    public static function sign(
        string $message,
        #[SensitiveParameter] string $secretKey,
        string $context = '',
        #[SensitiveParameter] ?string $randomness = null,
        ?string $mu = null
    ): string {
        self::assertLength($secretKey, 2560);
        self::assertContextLength($context);
        if ($randomness === null) {
            $randomness = random_bytes(32);
        }
        self::assertLength($randomness, 32);
        $params = new ParagonIE_Sodium_Core_MLDSA_Params();
        $rho = substr($secretKey, 0, 32);
        $vectors = [];
        $offset = 128;
        for ($v = 0; $v < 3; ++$v) {
            $vector = [];
            for ($i = 0; $i < 4; ++$i) {
                $bytes = self::stringToIntArray(
                    substr(
                        $secretKey,
                        $offset,
                        $v === 2 ? 416 : 96
                    )
                );
                if ($v !== 2) {
                    $encoded = ParagonIE_Sodium_Core_MLDSA_Operations::simpleBitUnpack($bytes, 3);
                    for ($j = 0; $j < 256; ++$j) {
                        if ($encoded[$j] > 4) {
                            throw new SodiumException('Invalid ML-DSA secret coefficient');
                        }
                        $encoded[$j] = 2 - $encoded[$j];
                    }
                    $poly = $encoded;
                } else {
                    $poly = ParagonIE_Sodium_Core_MLDSA_Operations::bitUnpack($bytes, 12);
                }
                $vector[] = ParagonIE_Sodium_Core_MLDSA_Ring::fromSymmetric($poly);
                $offset += $v === 2 ? 416 : 96;
            }
            $vectors[] = ParagonIE_Sodium_Core_MLDSA_Operations::nttVec($vector);
        }
        $key = new ParagonIE_Sodium_Core_MLDSA_InternalSigningKey(
            $params, $rho, substr($secretKey, 32, 32), substr($secretKey, 64, 64),
            $vectors[0], $vectors[1], $vectors[2],
            new ParagonIE_Sodium_Core_MLDSA_InternalVerificationKey($params, $rho, []),
            ParagonIE_Sodium_Core_MLDSA_Operations::expandA($params, $rho)
        );
        return $key->signInternal(
            ParagonIE_Sodium_Core_MLDSA_Operations::prepareMessage($message, $context),
            $randomness,
            $mu
        )->bytes();
    }

    /**
     * @internal
     * @psalm-suppress PossiblyUnusedMethod
     * @throws SodiumException
     */
    public static function signMu(
        string $mu,
        #[SensitiveParameter] string $secretKey,
        #[SensitiveParameter] string $randomness
    ): string {
        self::assertLength($mu, 64);
        return self::sign('', $secretKey, '', $randomness, $mu);
    }

    /**
     * @throws SodiumException
     */
    public static function verify(
        string $signature,
        string $message,
        string $publicKey,
        string $context = ''
    ): bool {
        self::assertLength($publicKey, 1312);
        self::assertContextLength($context);
        self::assertLength($signature, 2420);
        $params = new ParagonIE_Sodium_Core_MLDSA_Params();
        try {
            $decoded = ParagonIE_Sodium_Core_MLDSA_Operations::pkDecode($params, $publicKey);
            $key = new ParagonIE_Sodium_Core_MLDSA_InternalVerificationKey($params, $decoded[0], $decoded[1]);
            $sig = ParagonIE_Sodium_Core_MLDSA_InternalSignature::fromBytes($params, $signature);
            return $key->verifyInternal(
                $sig,
                ParagonIE_Sodium_Core_MLDSA_Operations::prepareMessage($message, $context)
            );
        } catch (SodiumException $ex) {
            return false;
        }
    }

    /**
     * @throws SodiumException
     */
    private static function assertContextLength(string $context): void
    {
        if (ParagonIE_Sodium_Core_Util::strlen($context) > 255) {
            throw new SodiumException('ML-DSA context must be at most 255 bytes');
        }
    }
}
