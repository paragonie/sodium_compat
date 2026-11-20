<?php

/**
 * ML-KEM-768, FIPS 203, with expanded secret keys.
 * @internal
 * @psalm-suppress PossiblyUnusedMethod
 */
final class ParagonIE_Sodium_Core_MLKEM768 extends ParagonIE_Sodium_Core_PQUtil
{
    /**
     * @throws SodiumException
     */
    public static function seedKeypair(#[SensitiveParameter] string $seed): string
    {
        self::assertLength($seed, 64);
        $key = ParagonIE_Sodium_Core_MLKem_Operations::kemKeyGen(
            3,
            2,
            substr($seed, 0, 32),
            substr($seed, 32, 32)
        );
        $secret = '';
        foreach ($key['s'] as $poly) {
            $secret .= ParagonIE_Sodium_Core_MLKem_Operations::polyByteEncode($poly);
        }
        $public = $key['encapsulationKeyBytes'];
        return $secret . $public . $key['h'] . substr($seed, 32, 32) . $public;
    }

    /**
     * @throws SodiumException
     */
    public static function enc(string $publicKey, #[SensitiveParameter] string $seed): array
    {
        self::assertLength($publicKey, 1184);
        self::assertLength($seed, 32);
        $key = ParagonIE_Sodium_Core_MLKem_Operations::parseEncapsulationKey(3, $publicKey);
        $result = ParagonIE_Sodium_Core_MLKem_Operations::kemEncaps(3, 2, 10, 4, $key, $seed);
        return [$result['ciphertext'], $result['sharedKey']];
    }

    /**
     * @throws SodiumException
     */
    public static function dec(string $ciphertext, #[SensitiveParameter] string $secretKey): string
    {
        self::assertLength($ciphertext, 1088);
        self::assertLength($secretKey, 2400);
        $s = [];
        for ($i = 0; $i < 3; ++$i) {
            $s[$i] = ParagonIE_Sodium_Core_MLKem_Operations::polyByteDecode(
                substr($secretKey, $i * 384, 384)
            );
        }
        $public = substr($secretKey, 1152, 1184);
        $h = substr($secretKey, 2336, 32);
        if (!ParagonIE_Sodium_Core_Util::hashEquals(ParagonIE_Sodium_Core_Keccak::sha3_256($public), $h)) {
            throw new SodiumException('Invalid ML-KEM secret key hash');
        }
        $key = ParagonIE_Sodium_Core_MLKem_Operations::parseEncapsulationKey(3, $public);
        return ParagonIE_Sodium_Core_MLKem_Operations::kemDecaps(
            3, 2, 10, 4, substr($secretKey, 2368, 32), $h, $key, $s, $ciphertext
        );
    }

    /**
     * Validate the FIPS 203 expanded-key invariants before native dispatch.
     * @throws SodiumException
     */
    public static function validateSecretKey(#[SensitiveParameter] string $secretKey): void
    {
        self::assertLength($secretKey, 2400);
        $public = substr($secretKey, 1152, 1184);
        if (!ParagonIE_Sodium_Core_Util::hashEquals(
            ParagonIE_Sodium_Core_Keccak::sha3_256($public),
            substr($secretKey, 2336, 32)
        )) {
            throw new SodiumException('Invalid ML-KEM secret key hash');
        }
        for ($i = 0; $i < 6; ++$i) {
            ParagonIE_Sodium_Core_MLKem_Operations::polyByteDecode(
                substr($secretKey, $i * 384, 384)
            );
        }
    }
}
