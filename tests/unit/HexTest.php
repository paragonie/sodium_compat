<?php

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class HexTest extends TestCase
{
    public static function hexProvider(): array
    {
        return array(
            array('DEADBEEF', '', "\xde\xad\xbe\xef", false),
            array('DeAdBeeF', '', "\xde\xad\xbe\xef", false),
            array("De\nAdBe\neF", "\n", "\xde\xad\xbe\xef", false),
            array("De\nAdBe eF", "\n", "\xde\xad\xbe\xef", true),
            array("De\nAdBe eF", "\n ", "\xde\xad\xbe\xef", false),
            array("De AdBe eF", " ", "\xde\xad\xbe\xef", false),
        );
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
