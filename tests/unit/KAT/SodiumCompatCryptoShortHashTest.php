<?php

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class SodiumCompatCryptoShortHashTest extends KnownAnswerTestCase
{
    /**
     * @return array<int, array<int, string>>
     */
    public static function successfulTestCases(): array
    {
        // From libsodium tests
        return [
            [
                '000102030405060708090a0b0c0d0e0f', // key
                'This is a test message.', // message
                'c0b48b757971e4a2',      // hash
            ],
        ];
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testShortHash(string $key, string $message, string $hash): void
    {
        $k = $this->hextobin($key);
        $m = $message;

        $calculatedHash = ParagonIE_Sodium_Compat::crypto_shorthash($m, $k);
        $this->assertSame(
            $hash,
            ParagonIE_Sodium_Compat::bin2hex($calculatedHash)
        );
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider("successfulTestCases")]
    public function testInvalidKeyLength(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Argument 2 must be CRYPTO_SHORTHASH_KEYBYTES long.');
        ParagonIE_Sodium_Compat::crypto_shorthash(
            'message',
            str_repeat("\x00", 15)
        );
    }
}
