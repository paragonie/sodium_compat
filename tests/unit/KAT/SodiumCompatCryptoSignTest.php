<?php

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class SodiumCompatCryptoSignTest extends KnownAnswerTestCase
{
    /**
     * @return array<int, array<int, string>>
     */
    public static function successfulTestCases(): array
    {
        return [
            [
                'This is a test message.', // message
                '4299d32d4825a2399587a80800a74790a2a8965f57f6f73379b3614838f50000', // sk_seed
                '3046067b579e1875418b329a285d24c9448981456314343d81b8e1585521405f', // pk
                '2745344399451998599485949812479124981248912489124891248912489124', // signature (placeholder)
            ],
        ];
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testCryptoSign(string $message, string $sk_seed, string $pk, string $signature): void
    {
        $seed = $this->hextobin($sk_seed);
        $keypair = ParagonIE_Sodium_Compat::crypto_sign_seed_keypair($seed);
        $secretKey = ParagonIE_Sodium_Compat::crypto_sign_secretkey($keypair);

        $signed = ParagonIE_Sodium_Compat::crypto_sign($message, $secretKey);
        $opened = ParagonIE_Sodium_Compat::crypto_sign_open($signed, ParagonIE_Sodium_Compat::crypto_sign_publickey($keypair));

        $this->assertSame($message, $opened);
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testCryptoSignDetached(string $message, string $sk_seed, string $pk, string $signature): void
    {
        $seed = $this->hextobin($sk_seed);
        $keypair = ParagonIE_Sodium_Compat::crypto_sign_seed_keypair($seed);
        $secretKey = ParagonIE_Sodium_Compat::crypto_sign_secretkey($keypair);
        $publicKey = ParagonIE_Sodium_Compat::crypto_sign_publickey($keypair);
        
        $sig = ParagonIE_Sodium_Compat::crypto_sign_detached($message, $secretKey);
        $this->assertTrue(
            ParagonIE_Sodium_Compat::crypto_sign_verify_detached($sig, $message, $publicKey)
        );
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testCryptoSignKeyPair(string $message, string $sk_seed, string $pk, string $signature): void
    {
        $seed = $this->hextobin($sk_seed);
        $keypair = ParagonIE_Sodium_Compat::crypto_sign_seed_keypair($seed);
        $this->assertSame(96, strlen($keypair));
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testCryptoSignEd25519PkToCurve25519(string $message, string $sk_seed, string $pk, string $signature): void
    {
        $ed25519_pk = $this->hextobin($pk);
        $curve25519_pk = ParagonIE_Sodium_Compat::crypto_sign_ed25519_pk_to_curve25519($ed25519_pk);
        $this->assertSame(32, strlen($curve25519_pk));
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testCryptoSignEd25519SkToCurve25519(string $message, string $sk_seed, string $pk, string $signature): void
    {
        $seed = $this->hextobin($sk_seed);
        $keypair = ParagonIE_Sodium_Compat::crypto_sign_seed_keypair($seed);
        $ed25519_sk = ParagonIE_Sodium_Compat::crypto_sign_secretkey($keypair);
        $curve25519_sk = ParagonIE_Sodium_Compat::crypto_sign_ed25519_sk_to_curve25519($ed25519_sk);
        $this->assertSame(32, strlen($curve25519_sk));
    }
}
