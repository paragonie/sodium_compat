<?php

final class ParagonIE_Sodium_Core_XWing extends ParagonIE_Sodium_Core_PQUtil
{
    /**
     * @throws SodiumException
     */
    public static function seedKeypair(#[SensitiveParameter] string $seed): string
    {
        self::assertLength($seed, 32);
        $expanded = ParagonIE_Sodium_Core_Keccak::shake256()
            ->absorb($seed)
            ->squeeze(96);
        $mlkem = ParagonIE_Sodium_Core_MLKEM768::seedKeypair(substr($expanded, 0, 64));
        $publicX = ParagonIE_Sodium_Compat::crypto_scalarmult_base(substr($expanded, 64, 32));
        return $seed . substr($mlkem, 2400) . $publicX;
    }

    /**
     * @throws SodiumException
     */
    public static function enc(string $publicKey, #[SensitiveParameter] string $seed): array
    {
        self::assertLength($publicKey, 1216);
        self::assertLength($seed, 64);
        $mlkem = ParagonIE_Sodium_Core_MLKEM768::enc(
            substr($publicKey, 0, 1184),
            substr($seed, 0, 32)
        );
        $publicX = substr($publicKey, 1184, 32);
        $secretX = substr($seed, 32, 32);
        $cipherX = ParagonIE_Sodium_Compat::crypto_scalarmult_base($secretX);
        $sharedX = ParagonIE_Sodium_Compat::crypto_scalarmult($secretX, $publicX);
        return [
            $mlkem[0] . $cipherX,
            self::combine($mlkem[1], $sharedX, $cipherX, $publicX)
        ];
    }

    /**
     * @throws SodiumException
     */
    public static function dec(string $ciphertext, #[SensitiveParameter] string $secretKey): string
    {
        self::assertLength($ciphertext, 1120);
        self::assertLength($secretKey, 32);
        $expanded = ParagonIE_Sodium_Core_Keccak::shake256()
            ->absorb($secretKey)
            ->squeeze(96);
        $mlkem = ParagonIE_Sodium_Core_MLKEM768::seedKeypair(substr($expanded, 0, 64));
        $secretX = substr($expanded, 64, 32);
        $publicX = ParagonIE_Sodium_Compat::crypto_scalarmult_base($secretX);
        $cipherX = substr($ciphertext, 1088, 32);
        $shared = ParagonIE_Sodium_Core_MLKEM768::dec(
            substr($ciphertext, 0, 1088),
            substr($mlkem, 0, 2400)
        );
        $sharedX = ParagonIE_Sodium_Compat::crypto_scalarmult($secretX, $cipherX);
        return self::combine($shared, $sharedX, $cipherX, $publicX);
    }

    private static function combine(string $mlkem, string $x25519, string $cipherX, string $publicX): string
    {
        return ParagonIE_Sodium_Core_Keccak::sha3_256(
            $mlkem .
            $x25519 .
            $cipherX .
            $publicX .
            "\x5c\x2e\x2f\x2f\x5e\x5c"
        );
    }
}
