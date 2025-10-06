<?php

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class SodiumCompatCryptoGenericHashTest extends KnownAnswerTestCase
{
    /**
     * @return array<int, array<int, string>>
     */
    public static function successfulTestCases(): array
    {
        return [
            [
                '48124192471298471298471298479124', // key
                'This is a test message.', // message
                '4b10645c7f1a21f4532748e29e4e6fb748f5dee0a3e2284ddc0b90ffcd63b938', // hash
            ],
        ];
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testGenericHash(string $key, string $message, string $hash): void
    {
        $k = $this->hextobin($key);
        $m = $message;

        $calculatedHash = ParagonIE_Sodium_Compat::crypto_generichash($m, $k, 32);
        $this->assertSame(
            $hash,
            ParagonIE_Sodium_Compat::bin2hex($calculatedHash)
        );
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testGenericHashStreaming(string $key, string $message, string $hash): void
    {
        $k = $this->hextobin($key);
        $m1 = substr($message, 0, 10);
        $m2 = substr($message, 10);

        $state = ParagonIE_Sodium_Compat::crypto_generichash_init($k, 32);
        ParagonIE_Sodium_Compat::crypto_generichash_update($state, $m1);
        ParagonIE_Sodium_Compat::crypto_generichash_update($state, $m2);
        $calculatedHash = ParagonIE_Sodium_Compat::crypto_generichash_final($state, 32);

        $this->assertSame(
            $hash,
            ParagonIE_Sodium_Compat::bin2hex($calculatedHash)
        );
    }

    public function testInvalidKeyLengths(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Unsupported key size. Must be at least CRYPTO_GENERICHASH_KEYBYTES_MIN bytes long.');
        ParagonIE_Sodium_Compat::crypto_generichash(
            'message',
            str_repeat("\x00", 15)
        );
    }

    public function testInvalidKeyLengthsMax(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Unsupported key size. Must be at most CRYPTO_GENERICHASH_KEYBYTES_MAX bytes long.');
        ParagonIE_Sodium_Compat::crypto_generichash(
            'message',
            str_repeat("\x00", 65)
        );
    }
}
