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

    public static function absTestCases(): array
    {
        return [
            [123, 123],
            [-123, 123],
            [-1, 1],
            [-65535, 65535],
        ];
    }

    /**
     * @dataProvider absTestCases
     */
    #[DataProvider("absTestCases")]
    public function testAbs(int $before, int $after): void
    {
        $this->assertSame($after, ParagonIE_Sodium_Core_Util::abs($before));
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

        try {
            $val = '';
            ParagonIE_Sodium_Compat::increment($val);
            $this->fail('Empty string should not be allowed');
        } catch (SodiumException $ex) {
            $this->assertSame('Argument 1 cannot be empty', $ex->getMessage());
        }
    }

    public function testMemcmp(): void
    {
        $this->assertSame(0, ParagonIE_Sodium_Compat::memcmp('a', 'a'));
        $this->assertNotSame(0, ParagonIE_Sodium_Compat::memcmp('a', 'b'));
    }

    public function testMemzero(): void
    {
        if (!extension_loaded('sodium')) {
            $this->expectException(SodiumException::class);
            $this->expectExceptionMessage('This is not implemented in sodium_compat, as it is not possible to securely wipe memory from PHP. To fix this error, make sure libsodium is installed and the PHP extension is enabled.');
            $val = 'test';
            ParagonIE_Sodium_Compat::memzero($val);
        } else {
            $val = 'test';
            ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = false;
            ParagonIE_Sodium_Compat::memzero($val);
            ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
            $this->assertEmpty($val);
        }
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

        try {
            ParagonIE_Sodium_Compat::unpad("\x00", 8);
            $this->fail('Invalid padding should not be accepted');
        } catch (SodiumException $ex) {
            $this->assertSame('invalid padding', $ex->getMessage());
        }
        try {
            ParagonIE_Sodium_Compat::unpad("test\x00\x00\x00\x00", 8);
            $this->fail('Invalid padding should not be accepted');
        } catch (SodiumException $ex) {
            $this->assertSame('invalid padding', $ex->getMessage());
        }
    }

    /**
     * @dataProvider sodiumSubTestCases
     */
    #[DataProvider('sodiumSubTestCases')]
    public function testSub(string $a, string $b, string $expect, bool $shouldSucceed): void
    {
        if (!$shouldSucceed) {
            $this->expectException(SodiumException::class);
        }
        $expected = ParagonIE_Sodium_Compat::hex2bin($expect);
        $out = ParagonIE_Sodium_Compat::hex2bin($a);
        $br = ParagonIE_Sodium_Compat::hex2bin($b);
        ParagonIE_Sodium_Compat::sub($out, $br);
        $this->assertSame($expected, $out);
    }

    public static function sodiumSubTestCases(): array
    {
        return [
            ["79563412", "01000000", "78563412", true],
            ["785634", "01000000", "", false],
            ["78563412", "010000", "", false]
        ];
    }

    public function testBase64(): void
    {
        $this->assertSame('', ParagonIE_Sodium_Compat::bin2base64('', 1));
        $this->assertSame('', ParagonIE_Sodium_Compat::base642bin('', 1));

        $variants = array(
            ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL,
            ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL_NO_PADDING,
            ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE,
            ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE_NO_PADDING
        );
        $str = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.';

        foreach ($variants as $v) {
            $encoded = ParagonIE_Sodium_Compat::bin2base64($str, $v);
            $this->assertIsString($encoded);
            $decoded = ParagonIE_Sodium_Compat::base642bin($encoded, $v);
            $this->assertSame($str, $decoded);
        }

        try {
            ParagonIE_Sodium_Compat::bin2base64($str, 999);
            $this->fail('Invalid variant was accepted');
        } catch (SodiumException $ex) {
        }
        try {
            ParagonIE_Sodium_Compat::base642bin($str, 999);
            $this->fail('Invalid variant was accepted');
        } catch (SodiumException $ex) {
        }
        try {
            ParagonIE_Sodium_Compat::base642bin('this is not base64', 1);
            $this->fail('Invalid base64 was accepted');
        } catch (SodiumException $ex) {
        }
    }

    public function testRandom16(): void
    {
        for ($i = 0; $i < 100; ++$i) {
            $rand = ParagonIE_Sodium_Compat::randombytes_random16();
            $this->assertGreaterThanOrEqual(0, $rand);
            $this->assertLessThanOrEqual(0xffff, $rand);
        }
    }

    public function testRandomUniform(): void
    {
        for ($i = 2; $i < 256; ++$i) {
            $rand = ParagonIE_Sodium_Compat::randombytes_uniform($i);
            $this->assertGreaterThanOrEqual(0, $rand);
            $this->assertLessThan($i, $rand);
        }
    }

    public function testVersion(): void
    {
        $this->assertIsString(ParagonIE_Sodium_Compat::version_string());
        $this->assertIsInt(ParagonIE_Sodium_Compat::library_version_major());
        $this->assertIsInt(ParagonIE_Sodium_Compat::library_version_minor());
    }

    public function testPadUnpadLoop(): void
    {
        $message = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.';
        for ($i = 1; $i < 256; ++$i) {
            $padded = ParagonIE_Sodium_Compat::pad($message, $i, true);
            $unpadded = ParagonIE_Sodium_Compat::unpad($padded, $i, true);
            $this->assertSame($message, $unpadded, 'Block size ' . $i);
        }
    }

    public function testAndStrings(): void
    {
        $this->assertSame(
            '',
            ParagonIE_Sodium_Core_Util::andStrings('', '')
        );
        $this->assertSame(
            "\x00\x00\x00\x00",
            ParagonIE_Sodium_Core_Util::andStrings(
                "\xde\xad\xbe\xef",
                "\x00\x00\x00\x00"
            )
        );
        $this->assertSame(
            "\xde\xad\xbe\xef",
            ParagonIE_Sodium_Core_Util::andStrings(
                "\xde\xad\xbe\xef",
                "\xff\xff\xff\xff"
            )
        );
    }

    public function testAndStringsInvalidLength(): void
    {
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Core_Util::andStrings('a', 'ab');
    }

    public function testXorStrings(): void
    {
        $this->assertSame(
            '',
            ParagonIE_Sodium_Core_Util::xorStrings('', '')
        );
        $this->assertSame(
            "\xde\xad\xbe\xef",
            ParagonIE_Sodium_Core_Util::xorStrings(
                "\xde\xad\xbe\xef",
                "\x00\x00\x00\x00"
            )
        );
        $this->assertSame(
            "\x21\x52\x41\x10",
            ParagonIE_Sodium_Core_Util::xorStrings(
                "\xde\xad\xbe\xef",
                "\xff\xff\xff\xff"
            )
        );
        $this->assertSame(
            "\x03",
            ParagonIE_Sodium_Core_Util::xorStrings('a', 'b')
        );
    }

    public function testBin2Hex(): void
    {
        $this->assertSame('', ParagonIE_Sodium_Core_Util::bin2hex(''));
        $this->assertSame('deadbeef', ParagonIE_Sodium_Core_Util::bin2hex("\xde\xad\xbe\xef"));
    }

    public function testHex2Bin(): void
    {
        $this->assertSame('', ParagonIE_Sodium_Core_Util::hex2bin(''));
        $this->assertSame("\xde\xad\xbe\xef", ParagonIE_Sodium_Core_Util::hex2bin('deadbeef'));
        $this->assertSame(
            "\xde\xad\xbe\xef",
            ParagonIE_Sodium_Core_Util::hex2bin("de:ad:be:ef", ':')
        );
        $this->assertSame('', ParagonIE_Sodium_Core_Util::hex2bin('1'));
    }

    public function testHex2BinStrictPaddingException(): void
    {
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Core_Util::hex2bin('1', '', true);
    }

    public function testHex2BinInvalidCharsException(): void
    {
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Core_Util::hex2bin('invalid');
    }

    public function testChrToInt(): void
    {
        $this->assertSame(65, ParagonIE_Sodium_Core_Util::chrToInt('A'));
        $this->assertSame(128, ParagonIE_Sodium_Core_Util::chrToInt("\x80"));
    }

    public function testChrToIntInvalidLengthException(): void
    {
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Core_Util::chrToInt('invalid');
    }

    public function testIntToChr(): void
    {
        $this->assertSame('A', ParagonIE_Sodium_Core_Util::intToChr(65));
        $this->assertSame("\x80", ParagonIE_Sodium_Core_Util::intToChr(128));
    }

    public function testUtilCompare(): void
    {
        $this->assertSame(0, ParagonIE_Sodium_Core_Util::compare('a', 'a'));
        $this->assertSame(-1, ParagonIE_Sodium_Core_Util::compare('a', 'b'));
        $this->assertSame(1, ParagonIE_Sodium_Core_Util::compare('b', 'a'));
    }

    public function testUtilHashEquals(): void
    {
        $this->assertTrue(ParagonIE_Sodium_Core_Util::hashEquals('a', 'a'));
        $this->assertFalse(ParagonIE_Sodium_Core_Util::hashEquals('a', 'b'));
    }

    public function testUtilMemcmp(): void
    {
        $this->assertSame(0, ParagonIE_Sodium_Core_Util::memcmp('a', 'a'));
        $this->assertNotSame(0, ParagonIE_Sodium_Core_Util::memcmp('a', 'b'));
    }

    public function testVerify16(): void
    {
        $this->assertTrue(
            ParagonIE_Sodium_Core_Util::verify_16(
                str_repeat('a', 16),
                str_repeat('a', 16)
            )
        );
        $this->assertFalse(
            ParagonIE_Sodium_Core_Util::verify_16(
                str_repeat('a', 16),
                str_repeat('b', 16)
            )
        );
        $this->assertTrue(
            ParagonIE_Sodium_Core_Util::verify_16(
                str_repeat('a', 32),
                str_repeat('a', 32)
            )
        );
    }

    public function testVerify32(): void
    {
        $this->assertTrue(
            ParagonIE_Sodium_Core_Util::verify_32(
                str_repeat('a', 32),
                str_repeat('a', 32)
            )
        );
        $this->assertFalse(
            ParagonIE_Sodium_Core_Util::verify_32(
                str_repeat('a', 32),
                str_repeat('b', 32)
            )
        );
        $this->assertTrue(
            ParagonIE_Sodium_Core_Util::verify_32(
                str_repeat('a', 64),
                str_repeat('a', 64)
            )
        );
    }

    public function testIntArrayStringConversion(): void
    {
        $this->assertSame(
            '',
            ParagonIE_Sodium_Core_Util::intArrayToString([])
        );
        $this->assertSame(
            [],
            ParagonIE_Sodium_Core_Util::stringToIntArray('')
        );
        $expected = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        $this->assertSame(
            $expected,
            ParagonIE_Sodium_Core_Util::stringToIntArray(
                ParagonIE_Sodium_Core_Util::intArrayToString($expected)
            )
        );
        $expected = [255, 128, 0];
        $this->assertSame(
            $expected,
            ParagonIE_Sodium_Core_Util::stringToIntArray(
                ParagonIE_Sodium_Core_Util::intArrayToString($expected)
            )
        );
    }

    public function testLoad3(): void
    {
        $this->assertSame(0x010203, ParagonIE_Sodium_Core_Util::load_3("\x03\x02\x01"));
    }

    public function testLoad3InvalidLengthException(): void
    {
        $this->expectException(RangeException::class);
        ParagonIE_Sodium_Core_Util::load_3('ab');
    }

    public function testLoad4(): void
    {
        $this->assertSame(0x01020304, ParagonIE_Sodium_Core_Util::load_4("\x04\x03\x02\x01"));
    }

    public function testLoad4InvalidLengthException(): void
    {
        $this->expectException(RangeException::class);
        ParagonIE_Sodium_Core_Util::load_4('abc');
    }

    public function testLoadStore64(): void
    {
        $stored = ParagonIE_Sodium_Core_Util::store64_le(0x0102030405060708);
        $this->assertSame(0x0102030405060708, ParagonIE_Sodium_Core_Util::load64_le($stored));
    }

    public function testStore32(): void
    {
        $this->assertSame(
            "\x04\x03\x02\x01",
            ParagonIE_Sodium_Core_Util::store32_le(0x01020304)
        );
    }

    public static function mulProvider(): array
    {
        return [
            [2, 3, 6],
            [-2, 3, -6],
            [2, -3, -6],
            [-2, -3, 6],
            [0, 10, 0],
            [10, 0, 0],
            [65535, 65535, 4294836225]
        ];
    }

    /**
     * @dataProvider mulProvider
     */
    #[DataProvider("mulProvider")]
    public function testMul(int $a, int $b, int $expected): void
    {
        ParagonIE_Sodium_Compat::$fastMult = false;
        $this->assertSame($expected, ParagonIE_Sodium_Core_Util::mul($a, $b));
        ParagonIE_Sodium_Compat::$fastMult = true;
        $this->assertSame($expected, ParagonIE_Sodium_Core_Util::mul($a, $b));
    }

    public function testNumericTo64BitInteger(): void
    {
        $this->assertSame(
            [0, 1],
            ParagonIE_Sodium_Core_Util::numericTo64BitInteger(1)
        );
        $this->assertSame(
            [1, 0],
            ParagonIE_Sodium_Core_Util::numericTo64BitInteger(4294967296)
        );
    }

    public function testUtilStrlen(): void
    {
        $this->assertSame(0, ParagonIE_Sodium_Core_Util::strlen(''));
        $this->assertSame(4, ParagonIE_Sodium_Core_Util::strlen('test'));
        $this->assertSame(4, ParagonIE_Sodium_Core_Util::strlen("t\x00s\x00"));
    }

    public function testSubstr(): void
    {
        $this->assertSame('test', ParagonIE_Sodium_Core_Util::substr('test', 0));
        $this->assertSame('es', ParagonIE_Sodium_Core_Util::substr('test', 1, 2));
        $this->assertSame('', ParagonIE_Sodium_Core_Util::substr('test', 1, 0));
        $this->assertSame('st', ParagonIE_Sodium_Core_Util::substr('test', 2));
    }
}
