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
        for ($len = 1; $len <= 8; ++$len) {
            $random = random_bytes($len);
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
            ParagonIE_Sodium_Compat::base642bin('Zm9?vYg', SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING, '?')
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

    public static function trailingBitVectors(): array
    {
        $cases = [];
        foreach (self::variants() as [$variant]) {
            $urlSafe = in_array(
                $variant,
                [SODIUM_BASE64_VARIANT_URLSAFE, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING],
                true
            );
            $noPadding = in_array(
                $variant,
                [SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING],
                true
            );
            $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' . ($urlSafe ? '-_' : '+/');
            foreach (["\xff", "\xff\xff", str_repeat("\xa5", 32)] as $binary) {
                $encoded = base64_encode($binary);
                if ($urlSafe) {
                    $encoded = strtr($encoded, '+/', '-_');
                }
                if ($noPadding) {
                    $encoded = rtrim($encoded, '=');
                }
                $label = 'variant ' . $variant . ', ' . strlen($binary) . ' byte(s)';
                $cases[$label . ', canonical'] = [$encoded, $variant, $binary];
                $last = strlen(rtrim($encoded, '=')) - 1;
                $lastValue = strpos($alphabet, $encoded[$last]);
                $mask = strlen($binary) === 1 ? 15 : 3;
                for ($bits = 1; $bits <= $mask; ++$bits) {
                    $noncanonical = $encoded;
                    $noncanonical[$last] = $alphabet[$lastValue | $bits];
                    $cases[$label . ', unused bits ' . $bits] = [$noncanonical, $variant, null];
                }
            }
        }
        return $cases;
    }

    /**
     * @dataProvider trailingBitVectors
     * @throws SodiumException
     */
    #[DataProvider('trailingBitVectors')]
    public function testCanonicalTrailingBits(string $encoded, int $variant, ?string $expected): void
    {
        if ($expected === null) {
            $this->expectException(SodiumException::class);
            ParagonIE_Sodium_Compat::base642bin($encoded, $variant);
            return;
        }
        $this->assertSame($expected, ParagonIE_Sodium_Compat::base642bin($encoded, $variant));
    }

    /**
     * @dataProvider variants
     */
    #[DataProvider('variants')]
    public function testPaddingPolicy(int $variant): void
    {
        $noPadding = in_array(
            $variant,
            [SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING],
            true
        );
        $valid = $noPadding ? 'AA' : 'AA==';
        $invalid = $noPadding ? 'AA==' : 'AA';
        $this->assertSame("\x00", ParagonIE_Sodium_Compat::base642bin($valid, $variant));
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::base642bin($invalid, $variant);
    }

    /**
     * @dataProvider variants
     */
    #[DataProvider('variants')]
    public function testRejectsIncompleteQuartet(int $variant): void
    {
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::base642bin('A', $variant);
    }
}
