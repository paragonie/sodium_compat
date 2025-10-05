<?php

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class SodiumCompatMiscTest extends KnownAnswerTestCase
{
    /**
     * @dataProvider sodiumAddTestCases
     */
    #[DataProvider('sodiumAddTestCases')]
    public function testAdd(string $a, string $b, string $expect, bool $shouldSucceed): void
    {
        if (!$shouldSucceed) {
            $this->expectException(SodiumException::class);
        }
        $expected = ParagonIE_Sodium_Compat::hex2bin($expect);
        $out = ParagonIE_Sodium_Compat::hex2bin($a);
        $br = ParagonIE_Sodium_Compat::hex2bin($b);
        ParagonIE_Sodium_Compat::add($out, $br);
        $this->assertSame($expected, $out);
    }

    public static function sodiumAddTestCases(): array
    {
        return [
            ["", "", "", true],
            ["78563412", "01000000", "79563412", true],
            ["785634", "01000000", "", false],
            ["78563412", "010000", "", false]
        ];
    }
    
    public function testCompare(): void
    {
        $this->assertSame(0, ParagonIE_Sodium_Compat::compare('a', 'a'));
        $this->assertSame(-1, ParagonIE_Sodium_Compat::compare('a', 'b'));
        $this->assertSame(1, ParagonIE_Sodium_Compat::compare('b', 'a'));
    }

    public function testIncrement(): void
    {
        $val = str_repeat("\x00", 4);
        ParagonIE_Sodium_Compat::increment($val);
        $this->assertSame("\x01\x00\x00\x00", $val);

        $val = str_repeat("\xff", 4);
        ParagonIE_Sodium_Compat::increment($val);
        $this->assertSame("\x00\x00\x00\x00", $val);
    }

    public function testMemcmp(): void
    {
        $this->assertSame(0, ParagonIE_Sodium_Compat::memcmp('a', 'a'));
        $this->assertNotSame(0, ParagonIE_Sodium_Compat::memcmp('a', 'b'));
    }

    public function testMemzero(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('This is not implemented in sodium_compat, as it is not possible to securely wipe memory from PHP. To fix this error, make sure libsodium is installed and the PHP extension is enabled.');
        $val = 'test';
        ParagonIE_Sodium_Compat::memzero($val);
    }
    
    public function testPad(): void
    {
        $unpadded = 'test';
        $padded = ParagonIE_Sodium_Compat::pad($unpadded, 8);
        $this->assertSame(8, strlen($padded));
        $this->assertSame('test' . "\x80\x00\x00\x00", $padded);
    }

    public function testUnpad(): void
    {
        $padded = 'test' . "\x80\x00\x00\x00";
        $unpadded = ParagonIE_Sodium_Compat::unpad($padded, 8);
        $this->assertSame('test', $unpadded);
    }
}
