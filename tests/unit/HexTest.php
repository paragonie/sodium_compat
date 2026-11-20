<?php

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class HexTest extends TestCase
{
    public static function hexProvider(): array
    {
        return [
            ['DEADBEEF', '', "\xde\xad\xbe\xef", false],
            ['DeAdBeeF', '', "\xde\xad\xbe\xef", false],
            ["De\nAdBe\neF", "\n", "\xde\xad\xbe\xef", false],
            ["De\nAdBe eF", "\n", "\xde\xad\xbe\xef", true],
            ["De\nAdBe eF", "\n ", "\xde\xad\xbe\xef", false],
            ["De AdBe eF", " ", "\xde\xad\xbe\xef", false],
        ];
    }

    /**
     * @dataProvider hexProvider
     */
    #[DataProvider("hexProvider")]
    public function testHex2Bin($hex, $ignore, $binary, $fail): void
    {
        try {
            $decoded = ParagonIE_Sodium_Compat::hex2bin($hex, $ignore);
            $this->assertFalse($fail, 'This should have failed but did not!');
            $this->assertSame($binary, $decoded, 'Binary mismatch');
        } catch (RangeException|SodiumException $ex) {
            $this->assertTrue($fail, 'An unexpected hex2bin failure occurred');
        }
    }
}
