<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(ParagonIE_Sodium_Core_HChaCha20::class)]
class CoreHSalsa20Test extends TestCase
{
    /**
     * @dataProvider provideLibsodiumTestVectors
     */
    #[DataProvider("provideLibsodiumTestVectors")]
    public function testHsalsa20($expected, $key, $nonce)
    {
        $this->assertSame(
            $expected,
            ParagonIE_Sodium_Core_Util::bin2hex(
                ParagonIE_Sodium_Core_HSalsa20::hsalsa20(
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
                'f2a52d7cea2bb6babc32b07f89e22487a063c2481084ff41b8190fb7839d501c',
                '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
                '000102030405060708090a0b0c0d0e0f'
            ),
            array(
                '351f86faa3b988468a850122b65b0acece9c4826806aeee63de9c0da2bd7f91e',
                '0000000000000000000000000000000000000000000000000000000000000000',
                '00000000000000000000000000000000'
            )
        );
    }
}
