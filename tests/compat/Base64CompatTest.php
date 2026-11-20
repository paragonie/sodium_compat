<?php

use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class Base64CompatTest extends TestCase
{
    private bool $previousFallback;

    /**
     * @before
     */
    #[Before]
    public function before(): void
    {
        $this->previousFallback = ParagonIE_Sodium_Compat::$disableFallbackForUnitTests;
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Compat tests require ext-sodium');
        }
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @after
     */
    #[After]
    public function after(): void
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = $this->previousFallback;
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
        try {
            ParagonIE_Sodium_Compat::base642bin('Zm9vYg==', SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
            $this->fail('Should not have padding');
        } catch (SodiumException $ex) {
        }
    }

    public function testBadBase64Variants(): void
    {
        $this->assertSame('', ParagonIE_Sodium_Compat::base642bin('', SODIUM_BASE64_VARIANT_ORIGINAL));
        $this->assertSame('', ParagonIE_Sodium_Compat::bin2base64('', SODIUM_BASE64_VARIANT_ORIGINAL));

        try {
            ParagonIE_Sodium_Compat::base642bin('Zm9v', 12345);
            $this->fail('Invalid variant should throw an exception');
        } catch (SodiumException $ex) {
        }

        try {
            ParagonIE_Sodium_Compat::bin2base64('foo', 12345);
            $this->fail('Invalid variant should throw an exception');
        } catch (SodiumException $ex) {
        }

        try {
            ParagonIE_Sodium_Compat::base642bin('Zm9v-', SODIUM_BASE64_VARIANT_ORIGINAL, '');
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
    }

    public static function paddingVectors(): array
    {
        $encodings = [
            '', 'A', 'AA', 'AAA', 'AAAA', 'AAAAA', 'AAAAAA', 'AAAAAAA',
            'AA=', 'AA==', 'AA===', 'AAA=', 'AAA==', 'AAAA=',
            '====', 'A===', 'AA=A', 'Zg==', 'Zm8='
        ];
        $token = base64_encode(str_repeat("\xa5", 32));
        $last = strlen($token) - 2;
        foreach (['U', 'V', 'W', 'X'] as $tail) {
            $candidate = $token;
            $candidate[$last] = $tail;
            $encodings[] = $candidate;
            $encodings[] = rtrim($candidate, '=');
        }
        $cases = [];
        foreach ([
            SODIUM_BASE64_VARIANT_ORIGINAL,
            SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING,
            SODIUM_BASE64_VARIANT_URLSAFE,
            SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING
        ] as $variant) {
            foreach ($encodings as $encoded) {
                $cases['variant ' . $variant . ': ' . $encoded] = [$encoded, $variant];
            }
        }
        return $cases;
    }

    /**
     * @dataProvider paddingVectors
     */
    #[DataProvider('paddingVectors')]
    public function testPaddingMatchesNative(string $encoded, int $variant): void
    {
        $expected = null;
        try {
            $expected = sodium_base642bin($encoded, $variant);
        } catch (SodiumException $ex) {
        }
        $actual = null;
        try {
            $actual = ParagonIE_Sodium_Compat::base642bin($encoded, $variant);
        } catch (SodiumException $ex) {
        }
        $this->assertSame($expected, $actual);
    }

    public function testAllTwoCharacterEncodingsMatchNative(): void
    {
        $original = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        $urlSafe = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
        foreach ([
            SODIUM_BASE64_VARIANT_ORIGINAL => [$original, '=='],
            SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING => [$original, ''],
            SODIUM_BASE64_VARIANT_URLSAFE => [$urlSafe, '=='],
            SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING => [$urlSafe, '']
        ] as $variant => [$alphabet, $padding]) {
            $accepted = 0;
            for ($first = 0; $first < 64; ++$first) {
                for ($second = 0; $second < 64; ++$second) {
                    $encoded = $alphabet[$first] . $alphabet[$second] . $padding;
                    $expected = null;
                    try {
                        $expected = sodium_base642bin($encoded, $variant);
                        ++$accepted;
                    } catch (SodiumException $ex) {
                    }
                    $actual = null;
                    try {
                        $actual = ParagonIE_Sodium_Compat::base642bin($encoded, $variant);
                    } catch (SodiumException $ex) {
                    }
                    $this->assertSame($expected, $actual, 'Variant ' . $variant . ': ' . $encoded);
                }
            }
            $this->assertSame(256, $accepted);
        }
    }
}
