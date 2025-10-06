<?php

use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class Base64Test extends TestCase
{
    /**
     * @before
     */
    #[Before]
    public function before(): void
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    public static function variants(): array
    {
        return [
            [SODIUM_BASE64_VARIANT_ORIGINAL],
            [SODIUM_BASE64_VARIANT_URLSAFE],
            [SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING],
            [SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING],
        ];
    }

    /**
     * @dataProvider variants
     * @throws SodiumException
     */
    #[DataProvider("variants")]
    public function testEmpty(int $variant): void
    {
        $this->assertSame(
            '',
            ParagonIE_Sodium_Compat::base642bin('', $variant)
        );
        $this->assertSame(
            '',
            ParagonIE_Sodium_Compat::bin2base64('', $variant)
        );
    }

    public function testEncodeInvalidVariant(): void
    {
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::bin2base64('foo', 9999);
    }

    public function testDecodeInvalidVariant(): void
    {
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::base642bin('foo', 9999);
    }

    /**
     * @dataProvider variants
     * @throws Exception
     */
    #[DataProvider("variants")]
    public function testReversible(int $variant): void
    {
        for ($len = 0; $len < 8; ++$len) {
            $random = random_bytes(8);
            $encoded = ParagonIE_Sodium_Compat::bin2base64($random, $variant);
            $decoded = ParagonIE_Sodium_Compat::base642bin($encoded, $variant);
            $this->assertSame($random, $decoded);
        }
    }

    /**
     * @throws SodiumException
     */
    public function testBase642BinVariants(): void
    {
        $this->assertSame(
            'foo',
            ParagonIE_Sodium_Compat::base642bin('Zm9v', SODIUM_BASE64_VARIANT_ORIGINAL)
        );
        $this->assertSame(
            'foo',
            ParagonIE_Sodium_Compat::base642bin('Zm9v', SODIUM_BASE64_VARIANT_URLSAFE)
        );

        // Standard
        try {
            ParagonIE_Sodium_Compat::base642bin('Zm9v-', SODIUM_BASE64_VARIANT_ORIGINAL);
            $this->fail('Invalid character for variant');
        } catch (SodiumException $ex) {
        }
        try {
            ParagonIE_Sodium_Compat::base642bin('Zm9v_', SODIUM_BASE64_VARIANT_ORIGINAL);
            $this->fail('Invalid character for variant');
        } catch (SodiumException $ex) {
        }

        // URL-safe
        try {
            ParagonIE_Sodium_Compat::base642bin('Zm9v+', SODIUM_BASE64_VARIANT_URLSAFE);
            $this->fail('Invalid character for variant');
        } catch (SodiumException $ex) {
        }
        try {
            ParagonIE_Sodium_Compat::base642bin('Zm9v/', SODIUM_BASE64_VARIANT_URLSAFE);
            $this->fail('Invalid character for variant');
        } catch (SodiumException $ex) {
        }

        // No padding
        $this->assertSame(
            'foob',
            ParagonIE_Sodium_Compat::base642bin('Zm9vYg', SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING)
        );
        $this->assertSame(
            'foob',
            ParagonIE_Sodium_Compat::base642bin('Zm9vYg', SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING)
        );

        try {
            ParagonIE_Sodium_Compat::base642bin('Zm9vYg==', SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
            $this->fail('Should not have padding');
        } catch (SodiumException $ex) {
        }
        try {
            ParagonIE_Sodium_Compat::base642bin('Zm9vYg==', SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
            $this->fail('Should not have padding');
        } catch (SodiumException $ex) {
        }
    }

    /**
     * @throws SodiumException
     */
    public function testBase642BinIgnore(): void
    {
        $this->assertSame(
            'foob',
            ParagonIE_Sodium_Compat::base642bin('Zm9?vYg==', SODIUM_BASE64_VARIANT_ORIGINAL, '?')
        );
        $this->assertSame(
            'foob',
            ParagonIE_Sodium_Compat::base642bin('Zm9?vYg', SODIUM_BASE64_VARIANT_ORIGINAL, '?')
        );
    }

    /**
     * @throws SodiumException
     */
    public function testBin2Base64Variants(): void
    {
        $this->assertSame(
            'Zm9v',
            ParagonIE_Sodium_Compat::bin2base64('foo', SODIUM_BASE64_VARIANT_ORIGINAL)
        );
        $this->assertSame(
            'Zm9v',
            ParagonIE_Sodium_Compat::bin2base64('foo', SODIUM_BASE64_VARIANT_URLSAFE)
        );
        $this->assertSame(
            'Zm9vYg==',
            ParagonIE_Sodium_Compat::bin2base64('foob', SODIUM_BASE64_VARIANT_ORIGINAL)
        );
        $this->assertSame(
            'Zm9vYg',
            ParagonIE_Sodium_Compat::bin2base64('foob', SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING)
        );
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('invalid base64 variant identifier');
        ParagonIE_Sodium_Compat::bin2base64('foob', 9999);
    }
}
