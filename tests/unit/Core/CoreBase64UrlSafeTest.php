<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(ParagonIE_Sodium_Core_Base64_UrlSafe::class)]
class CoreBase64UrlSafeTest extends TestCase
{
    /**
     * @dataProvider provideTestStrings
     */
    #[DataProvider("provideTestStrings")]
    public function testEncodeDecode(string $input): void
    {
        $encoded = ParagonIE_Sodium_Core_Base64_UrlSafe::encode($input);
        $decoded = ParagonIE_Sodium_Core_Base64_UrlSafe::decode($encoded);
        $this->assertSame($input, $decoded, 'Encode/Decode reversibility');
    }

    public function testEncodeUnpadded(): void
    {
        $input = 'test'; // "dGVzdA=="
        $encoded = ParagonIE_Sodium_Core_Base64_UrlSafe::encodeUnpadded($input);
        $this->assertSame('dGVzdA', $encoded);
        $decoded = ParagonIE_Sodium_Core_Base64_UrlSafe::decode($encoded);
        $this->assertSame($input, $decoded);
    }

    public function testAlphabet(): void
    {
        // This specific input results in '+' and '/' in standard Base64
        $input = "\xfb\xff\xbf"; // Standard base64: +/+v
        $encoded = ParagonIE_Sodium_Core_Base64_UrlSafe::encode($input);
        $this->assertSame('-_-_', $encoded);

        $decoded = ParagonIE_Sodium_Core_Base64_UrlSafe::decode($encoded);
        $this->assertSame($input, $decoded);
    }

    public function testDecodeWithInvalidChars(): void
    {
        $this->expectException(RangeException::class);
        // Should not accept standard Base64 characters
        ParagonIE_Sodium_Core_Base64_UrlSafe::decode('+/+v');
    }

    public static function provideTestStrings(): array
    {
        return array(
            array(''),
            array('f'),
            array('fo'),
            array('foo'),
            array('foob'),
            array('fooba'),
            array('foobar'),
            array(random_bytes(33)),
            array(random_bytes(128))
        );
    }
}
