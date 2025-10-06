<?php

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class SodiumCompatCryptoKdfTest extends KnownAnswerTestCase
{
    /**
     * @return array<int, array<int, mixed>>
     */
    public static function successfulTestCases(): array
    {
        // Generated from a running libsodium instance
        return [
            [
                32, // subkey_len
                1, // subkey_id
                'testsodi', // context
                '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', // key
                'd19641075a8ec67bb916ace4644be250dc90d719182490a898b707eb1f3f3f75', // derived key
            ],
        ];
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testDeriveFromKey(int $subkey_len, int $subkey_id, string $context, string $key, string $expectedDerivedKey): void
    {
        $k = $this->hextobin($key);
        $c = $context;

        $derivedKey = ParagonIE_Sodium_Compat::crypto_kdf_derive_from_key($subkey_len, $subkey_id, $c, $k);
        $this->assertSame(
            $expectedDerivedKey,
            ParagonIE_Sodium_Compat::bin2hex($derivedKey)
        );
    }

    public function testKeygen(): void
    {
        $key = ParagonIE_Sodium_Compat::crypto_kdf_keygen();
        $this->assertSame(32, strlen($key));
    }
    
    public function testInvalidSubkeyLength(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('subkey cannot be smaller than SODIUM_CRYPTO_KDF_BYTES_MIN');
        ParagonIE_Sodium_Compat::crypto_kdf_derive_from_key(
            15,
            1,
            'testsodi',
            str_repeat("\x00", 32)
        );
    }

    public function testInvalidSubkeyLengthMax(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('subkey cannot be larger than SODIUM_CRYPTO_KDF_BYTES_MAX');
        ParagonIE_Sodium_Compat::crypto_kdf_derive_from_key(
            65,
            1,
            'testsodi',
            str_repeat("\x00", 32)
        );
    }

    public function testInvalidContextLength(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('context should be SODIUM_CRYPTO_KDF_CONTEXTBYTES bytes');
        ParagonIE_Sodium_Compat::crypto_kdf_derive_from_key(
            32,
            1,
            'short',
            str_repeat("\x00", 32)
        );
    }

    public function testInvalidKeyLength(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('key should be SODIUM_CRYPTO_KDF_KEYBYTES bytes');
        ParagonIE_Sodium_Compat::crypto_kdf_derive_from_key(
            32,
            1,
            'testsodi',
            str_repeat("\x00", 31)
        );
    }
}
