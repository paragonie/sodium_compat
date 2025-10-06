<?php

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class SodiumCompatCryptoAuthTest extends KnownAnswerTestCase
{
    /**
     * @return array<int, array<int, string>>
     */
    public static function successfulTestCases(): array
    {
        // From libsodium
        return [
            [
                'c7891782356784e104332938198f868207980293498409235898b98234980a92', // key
                '8e9997ebb26123456789', // message
                'b38282829f7ff34e9ec18bd75dba288d2bf0151326485a9b962fb6c464c03fdd', // mac
            ],
        ];
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testAuth(string $key, string $message, string $mac): void
    {
        $k = $this->hextobin($key);
        $m = $this->hextobin($message);

        $calculatedMac = ParagonIE_Sodium_Compat::crypto_auth($m, $k);
        $this->assertSame(
            $mac,
            ParagonIE_Sodium_Compat::bin2hex($calculatedMac)
        );
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testVerify(string $key, string $message, string $mac): void
    {
        $k = $this->hextobin($key);
        $m = $this->hextobin($message);
        $validMac = $this->hextobin($mac);

        $this->assertTrue(
            ParagonIE_Sodium_Compat::crypto_auth_verify($validMac, $m, $k)
        );
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testVerifyFailures(string $key, string $message, string $mac): void
    {
        $k = $this->hextobin($key);
        $m = $this->hextobin($message);
        $invalidMac = str_repeat("\x00", 32);

        $this->assertFalse(
            ParagonIE_Sodium_Compat::crypto_auth_verify($invalidMac, $m, $k)
        );
    }

    public function testInvalidKeyLengths(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Argument 2 must be CRYPTO_AUTH_KEYBYTES long.');
        ParagonIE_Sodium_Compat::crypto_auth(
            'message',
            str_repeat("\x00", 31)
        );
    }

    public function testInvalidMacLengths(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Argument 1 must be CRYPTO_AUTH_BYTES long.');
        ParagonIE_Sodium_Compat::crypto_auth_verify(
            str_repeat("\x00", 31),
            'message',
            str_repeat("\x00", 32)
        );
    }

    public function testEmptyInputs(): void
    {
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::crypto_auth('', '');
    }
}
