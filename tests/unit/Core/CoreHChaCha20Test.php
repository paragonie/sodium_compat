<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(ParagonIE_Sodium_Core_HChaCha20::class)]
class CoreHChaCha20Test extends TestCase
{
    /**
     * @dataProvider provideLibsodiumTestVectors
     */
    #[DataProvider("provideLibsodiumTestVectors")]
    public function testHChaCha20($expected, $key, $nonce)
    {
        $this->assertSame(
            $expected,
            ParagonIE_Sodium_Core_Util::bin2hex(
                ParagonIE_Sodium_Core_HChaCha20::hChaCha20(
                    ParagonIE_Sodium_Core_Util::hex2bin($nonce),
                    ParagonIE_Sodium_Core_Util::hex2bin($key)
                )
            )
        );
    }

    public static function provideLibsodiumTestVectors(): array
    {
        return array(
            array(
                '51e3ff45a895675c4b33b46c64f4a9ace110d34df6a2ceab486372bacbd3eff6',
                '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
                '000102030405060708090a0b0c0d0e0f'
            ),
            array(
                '1140704c328d1d5d0e30086cdf209dbd6a43b8f41518a11cc387b669b2ee6586',
                '0000000000000000000000000000000000000000000000000000000000000000',
                '00000000000000000000000000000000'
            )
        );
    }

    public function testInvalidKeyLength(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Argument 2 must be 32 bytes');
        ParagonIE_Sodium_Core_HChaCha20::hChaCha20(
            str_repeat("\x00", 16),
            str_repeat("\x00", 31)
        );
    }

    public function testInvalidNonceLength(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Argument 1 must be 16 bytes');
        ParagonIE_Sodium_Core_HChaCha20::hChaCha20(
            str_repeat("\x00", 15),
            str_repeat("\x00", 32)
        );
    }
}
