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

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testCryptoStream(int $length, string $nonce, string $key, string $message): void
    {
        $n = $this->hextobin($nonce);
        $k = $this->hextobin($key);

        $stream = ParagonIE_Sodium_Compat::crypto_stream($length, $n, $k);
        $this->assertSame($length, strlen($stream));
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testCryptoStreamXor(int $length, string $nonce, string $key, string $message): void
    {
        $n = $this->hextobin($nonce);
        $k = $this->hextobin($key);

        $encrypted = ParagonIE_Sodium_Compat::crypto_stream_xor($message, $n, $k);
        $decrypted = ParagonIE_Sodium_Compat::crypto_stream_xor($encrypted, $n, $k);
        $this->assertSame($message, $decrypted);
    }

    /**
     * @throws SodiumException
     */
    public function testXChaCha20OffBYOne(): void
    {
        $key = str_repeat("\x00", 32);
        $nonce = str_repeat("\x00", 24);
        $nonce2 = str_repeat("\x00", 15) . "\x01" . str_repeat("\x00", 8);
        $nonce3 = str_repeat("\x00", 16) . "\x01" . str_repeat("\x00", 7);

        $stream = ParagonIE_Sodium_Core_XChaCha20::stream(64, $nonce, $key);
        $this->assertNotSame(
            bin2hex($stream),
            bin2hex(ParagonIE_Sodium_Core_XChaCha20::stream(64, $nonce2, $key))
        );
        $this->assertNotSame(
            bin2hex($stream),
            bin2hex(ParagonIE_Sodium_Core_XChaCha20::stream(64, $nonce3, $key))
        );

        $stream = ParagonIE_Sodium_Core_XChaCha20::ietfStream(64, $nonce, $key);
        $this->assertNotSame(
            bin2hex($stream),
            bin2hex(ParagonIE_Sodium_Core_XChaCha20::ietfStream(64, $nonce2, $key))
        );
        $this->assertNotSame(
            bin2hex($stream),
            bin2hex(ParagonIE_Sodium_Core_XChaCha20::ietfStream(64, $nonce3, $key))
        );

        $message = random_bytes(64);
        $stream = ParagonIE_Sodium_Core_XChaCha20::streamXorIc($message, $nonce, $key);
        $this->assertNotSame(
            bin2hex($stream),
            bin2hex(ParagonIE_Sodium_Core_XChaCha20::streamXorIc($message, $nonce2, $key))
        );
        $this->assertNotSame(
            bin2hex($stream),
            bin2hex(ParagonIE_Sodium_Core_XChaCha20::streamXorIc($message, $nonce3, $key))
        );

        $stream = ParagonIE_Sodium_Core_XChaCha20::ietfStreamXorIc($message, $nonce, $key);
        $this->assertNotSame(
            bin2hex($stream),
            bin2hex(ParagonIE_Sodium_Core_XChaCha20::ietfStreamXorIc($message, $nonce2, $key))
        );
        $this->assertNotSame(
            bin2hex($stream),
            bin2hex(ParagonIE_Sodium_Core_XChaCha20::ietfStreamXorIc($message, $nonce3, $key))
        );
    }

    public function testXSalsa20OffBYOne(): void
    {
        $key = str_repeat("\x00", 32);
        $nonce = str_repeat("\x00", 24);
        $nonce2 = str_repeat("\x00", 15) . "\x01" . str_repeat("\x00", 8);
        $nonce3 = str_repeat("\x00", 16) . "\x01" . str_repeat("\x00", 7);

        $stream = ParagonIE_Sodium_Core_XSalsa20::xsalsa20(64, $nonce, $key);
        $this->assertNotSame(
            bin2hex($stream),
            bin2hex(ParagonIE_Sodium_Core_XSalsa20::xsalsa20(64, $nonce2, $key))
        );
        $this->assertNotSame(
            bin2hex($stream),
            bin2hex(ParagonIE_Sodium_Core_XSalsa20::xsalsa20(64, $nonce3, $key))
        );

        $message = random_bytes(64);
        $stream = ParagonIE_Sodium_Core_XSalsa20::xsalsa20_xor($message, $nonce, $key);
        $this->assertNotSame(
            bin2hex($stream),
            bin2hex(ParagonIE_Sodium_Core_XSalsa20::xsalsa20_xor($message, $nonce2, $key))
        );
        $this->assertNotSame(
            bin2hex($stream),
            bin2hex(ParagonIE_Sodium_Core_XSalsa20::xsalsa20_xor($message, $nonce3, $key))
        );
    }
}
