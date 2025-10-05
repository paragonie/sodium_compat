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

    public static function xsalsa20Successful(): array
    {
        return [
            [
                65,
                'ffffffffffffffffffffffffffffffffffffffffffffffff',
                'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
                '24a698344c6131e226e948b69dcd16315b4ea42da447bfb8280fb01a1c3a179f8d8c233f73b4c2fe21565c54ff3709c6d84df149ba8c94bb9b4f4f97ed1b83ca99'
            ], [
                128,
                'ffffffffffffffffffffffffffffffffffffffffffffffff',
                'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
                '24a698344c6131e226e948b69dcd16315b4ea42da447bfb8280fb01a1c3a179f8d8c233f73b4c2fe21565c54ff3709c6d84df149ba8c94bb9b4f4f97ed1b83ca9907a42152dc3557046042151a535593e99bce13adacf37b478dc52830a7c8089ebf849955ae5b0643f73217d08ef3da240d5050c2039f740284459d7cb0768d'
            ]
        ];
    }

    /**
     * @dataProvider xsalsa20Successful
     */
    #[DataProvider("xsalsa20Successful")]
    public function testXsalsa20(int $length, string $nonce, string $key, string $expected): void
    {
        $n = $this->hextobin($nonce);
        $k = $this->hextobin($key);
        $stream = ParagonIE_Sodium_Core_XSalsa20::xsalsa20($length, $n, $k);
        $e = $this->hextobin($expected);
        $this->assertSame($e, $stream);
    }

    public static function xchacha20Successful(): array
    {
        return [
            [
                65,
                'ffffffffffffffffffffffffffffffffffffffffffffffff',
                'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
                'f7807febd9f2b91153ef6fa542e4084ceee548a2f9dd029b6ea04c67f5c10a7791beb332d9085a501d3cf7dba81040cfb2556db4796b63fc294fea7cf51654d4eb'
            ], [
                128,
                'ffffffffffffffffffffffffffffffffffffffffffffffff',
                'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
                'f7807febd9f2b91153ef6fa542e4084ceee548a2f9dd029b6ea04c67f5c10a7791beb332d9085a501d3cf7dba81040cfb2556db4796b63fc294fea7cf51654d4ebbfaa6813681870894d2e99225502d330e2e069489b22cf702b047367766b55a1fbc835b2e321372db05625ab6ffa320b9c6db78114c5d6b72671ad55e642b7'
            ]
        ];
    }

    /**
     * @dataProvider xchacha20Successful
     */
    #[DataProvider("xchacha20Successful")]
    public function testXchacha20(int $length, string $nonce, string $key, string $expected): void
    {
        $n = $this->hextobin($nonce);
        $k = $this->hextobin($key);
        $stream = ParagonIE_Sodium_Core_XChaCha20::stream($length, $n, $k);
        $e = $this->hextobin($expected);
        $this->assertSame($e, $stream);
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
