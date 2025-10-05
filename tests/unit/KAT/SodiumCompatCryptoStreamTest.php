<?php

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class SodiumCompatCryptoStreamTest extends KnownAnswerTestCase
{
    /**
     * @return array<int, array<int, mixed>>
     */
    public static function successfulTestCases(): array
    {
        // From libsodium tests
        return [
            [
                32, // length
                '000102030405060708090a0b0c0d0e0f1011121314151617', // nonce
                '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', // key
                'This is a test message.', // message
            ],
        ];
    }

    #[DataProvider('successfulTestCases')]
    public function testCryptoStream(int $length, string $nonce, string $key, string $message): void
    {
        $n = $this->hextobin($nonce);
        $k = $this->hextobin($key);

        $stream = ParagonIE_Sodium_Compat::crypto_stream($length, $n, $k);
        $this->assertSame($length, strlen($stream));
    }

    #[DataProvider('successfulTestCases')]
    public function testCryptoStreamXor(int $length, string $nonce, string $key, string $message): void
    {
        $n = $this->hextobin($nonce);
        $k = $this->hextobin($key);

        $encrypted = ParagonIE_Sodium_Compat::crypto_stream_xor($message, $n, $k);
        $decrypted = ParagonIE_Sodium_Compat::crypto_stream_xor($encrypted, $n, $k);
        $this->assertSame($message, $decrypted);
    }
}
