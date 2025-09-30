<?php

use PHPUnit\Framework\Attributes\BeforeClass;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class Base64Test extends TestCase
{
    /**
     * @before
     */
    #[BeforeClass]
    public function before(): void
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
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
            ParagonIE_Sodium_Compat::base642bin('Zm9vYg==', SODIUM_BASE64_VARIANT_ORIGINAL, '=')
        );
        $this->assertSame(
            'foob',
            ParagonIE_Sodium_Compat::base642bin('Zm9vYg', SODIUM_BASE64_VARIANT_ORIGINAL, '=')
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
    }
}
