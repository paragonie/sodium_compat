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
}
