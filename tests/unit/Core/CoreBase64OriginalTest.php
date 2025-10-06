<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(ParagonIE_Sodium_Core_Base64_Original::class)]
class CoreBase64OriginalTest extends TestCase
{
    /**
     * @dataProvider provideTestStrings
     */
    #[DataProvider("provideTestStrings")]
    public function testEncodeDecode(string $input): void
    {
        $encoded = ParagonIE_Sodium_Core_Base64_Original::encode($input);
        $decoded = ParagonIE_Sodium_Core_Base64_Original::decode($encoded);
        $this->assertSame($input, $decoded, 'Encode/Decode reversibility');
    }

    public function testEncodeUnpadded(): void
    {
        $input = 'test'; // "dGVzdA=="
        $encoded = ParagonIE_Sodium_Core_Base64_Original::encodeUnpadded($input);
        $this->assertSame('dGVzdA', $encoded);
        $decoded = ParagonIE_Sodium_Core_Base64_Original::decode($encoded);
        $this->assertSame($input, $decoded);
    }

    /**
     * @dataProvider provideTestStrings
     */
    #[DataProvider("provideTestStrings")]
    public function testAgainstNative(string $input): void
    {
        $nativeEncoded = base64_encode($input);
        $ourEncoded = ParagonIE_Sodium_Core_Base64_Original::encode($input);
        $this->assertSame($nativeEncoded, $ourEncoded, 'Encode vs native');

        $ourDecoded = ParagonIE_Sodium_Core_Base64_Original::decode($nativeEncoded);
        $this->assertSame($input, $ourDecoded, 'Decode vs native');
    }

    public function testDecodeInvalidChars(): void
    {
        $this->expectException(RangeException::class);
        ParagonIE_Sodium_Core_Base64_Original::decode('not-base64!');
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
