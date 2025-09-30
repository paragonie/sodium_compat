<?php

use PHPUnit\Framework\Attributes\BeforeClass;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class Base64CompatTest extends TestCase
{
    /**
     * @before
     */
    #[BeforeClass]
    public function before(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Compat tests require ext-sodium');
        }
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @throws SodiumException
     */
    public function testBase642BinVariants(): void
    {
        $this->assertSame(
            'foo',
            sodium_base642bin('Zm9v', SODIUM_BASE64_VARIANT_ORIGINAL)
        );
        $this->assertSame(
            'foo',
            sodium_base642bin('Zm9v', SODIUM_BASE64_VARIANT_URLSAFE)
        );

        // Standard
        try {
            sodium_base642bin('Zm9v-', SODIUM_BASE64_VARIANT_ORIGINAL);
            $this->fail('Invalid character for variant');
        } catch (SodiumException $ex) {
        }
        try {
            sodium_base642bin('Zm9v_', SODIUM_BASE64_VARIANT_ORIGINAL);
            $this->fail('Invalid character for variant');
        } catch (SodiumException $ex) {
        }

        // URL-safe
        try {
            sodium_base642bin('Zm9v+', SODIUM_BASE64_VARIANT_URLSAFE);
            $this->fail('Invalid character for variant');
        } catch (SodiumException $ex) {
        }
        try {
            sodium_base642bin('Zm9v/', SODIUM_BASE64_VARIANT_URLSAFE);
            $this->fail('Invalid character for variant');
        } catch (SodiumException $ex) {
        }

        // No padding
        $this->assertSame(
            'foob',
            sodium_base642bin('Zm9vYg', SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING)
        );
        $this->assertSame(
            'foob',
            sodium_base642bin('Zm9vYg', SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING)
        );

        try {
            sodium_base642bin('Zm9vYg==', SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
            $this->fail('Should not have padding');
        } catch (SodiumException $ex) {
        }
        try {
            sodium_base642bin('Zm9vYg==', SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
            $this->fail('Should not have padding');
        } catch (SodiumException $ex) {
        }
        try {
            sodium_base642bin('Zm9vYg==', SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
            $this->fail('Should not have padding');
        } catch (SodiumException $ex) {
        }
    }

    public function testBadBase64Variants(): void
    {
        $this->assertSame('', sodium_base642bin('', SODIUM_BASE64_VARIANT_ORIGINAL));
        $this->assertSame('', sodium_bin2base64('', SODIUM_BASE64_VARIANT_ORIGINAL));

        try {
            sodium_base642bin('Zm9v', 12345);
            $this->fail('Invalid variant should throw an exception');
        } catch (SodiumException $ex) {
        }

        try {
            sodium_bin2base64('foo', 12345);
            $this->fail('Invalid variant should throw an exception');
        } catch (SodiumException $ex) {
        }

        try {
            sodium_base642bin('Zm9v-', SODIUM_BASE64_VARIANT_ORIGINAL, '');
            $this->fail('Invalid character for variant');
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
            sodium_base642bin('Zm9?vYg==', SODIUM_BASE64_VARIANT_ORIGINAL, '?')
        );
        $this->assertSame(
            'foob',
            sodium_base642bin('Zm9?vYg', SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING, '?')
        );
    }

    /**
     * @throws SodiumException
     */
    public function testBin2Base64Variants(): void
    {
        $this->assertSame(
            'Zm9v',
            sodium_bin2base64('foo', SODIUM_BASE64_VARIANT_ORIGINAL)
        );
        $this->assertSame(
            'Zm9v',
            sodium_bin2base64('foo', SODIUM_BASE64_VARIANT_URLSAFE)
        );
        $this->assertSame(
            'Zm9vYg==',
            sodium_bin2base64('foob', SODIUM_BASE64_VARIANT_ORIGINAL)
        );
        $this->assertSame(
            'Zm9vYg',
            sodium_bin2base64('foob', SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING)
        );
    }
}
