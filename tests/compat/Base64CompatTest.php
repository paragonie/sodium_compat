<?php

/**
 * @covers ParagonIE_Sodium_Compat
 */
class Base64CompatTest extends PHPUnit_Framework_TestCase
{
    /** @var bool */
    private $previousFallback;
    /**
     * @before
     */
    public function before()
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
    public function after()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = $this->previousFallback;
    }

    /**
     * @throws SodiumException
     */
    public function testBase642BinVariants()
    {
        $this->assertSame(
            'foo',
            ParagonIE_Sodium_Compat::base642bin('Zm9v', ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL)
        );
        $this->assertSame(
            'foo',
            ParagonIE_Sodium_Compat::base642bin('Zm9v', ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE)
        );
        // Standard
        try {
            ParagonIE_Sodium_Compat::base642bin('Zm9v-', ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL);
            $this->fail('Invalid character for variant');
        } catch (SodiumException $ex) {
        }
        try {
            ParagonIE_Sodium_Compat::base642bin('Zm9v_', ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL);
            $this->fail('Invalid character for variant');
        } catch (SodiumException $ex) {
        }
        // URL-safe
        try {
            ParagonIE_Sodium_Compat::base642bin('Zm9v+', ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE);
            $this->fail('Invalid character for variant');
        } catch (SodiumException $ex) {
        }
        try {
            ParagonIE_Sodium_Compat::base642bin('Zm9v/', ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE);
            $this->fail('Invalid character for variant');
        } catch (SodiumException $ex) {
        }
        // No padding
        $this->assertSame(
            'foob',
            ParagonIE_Sodium_Compat::base642bin('Zm9vYg', ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL_NO_PADDING)
        );
        $this->assertSame(
            'foob',
            ParagonIE_Sodium_Compat::base642bin('Zm9vYg', ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE_NO_PADDING)
        );
        try {
            ParagonIE_Sodium_Compat::base642bin('Zm9vYg==', ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL_NO_PADDING);
            $this->fail('Should not have padding');
        } catch (SodiumException $ex) {
        }
        try {
            ParagonIE_Sodium_Compat::base642bin('Zm9vYg==', ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE_NO_PADDING);
            $this->fail('Should not have padding');
        } catch (SodiumException $ex) {
        }
        try {
            ParagonIE_Sodium_Compat::base642bin('Zm9vYg==', ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL_NO_PADDING);
            $this->fail('Should not have padding');
        } catch (SodiumException $ex) {
        }
    }

    public function testBadBase64Variants()
    {
        $this->assertSame(
            '',
            ParagonIE_Sodium_Compat::base642bin('', ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL)
        );
        $this->assertSame(
            '',
            ParagonIE_Sodium_Compat::bin2base64('', ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL)
        );
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
            ParagonIE_Sodium_Compat::base642bin(
                'Zm9v-',
                ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL, ''
            );
            $this->fail('Invalid character for variant');
        } catch (SodiumException $ex) {
        }
    }

    /**
     * @throws SodiumException
     */
    public function testBase642BinIgnore()
    {
        $this->assertSame(
            'foob',
            ParagonIE_Sodium_Compat::base642bin('Zm9?vYg==', ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL, '?')
        );
        $this->assertSame(
            'foob',
            ParagonIE_Sodium_Compat::base642bin('Zm9?vYg', ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL_NO_PADDING, '?')
        );
    }

    /**
     * @throws SodiumException
     */
    public function testBin2Base64Variants()
    {
        $this->assertSame(
            'Zm9v',
            ParagonIE_Sodium_Compat::bin2base64('foo', ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL)
        );
        $this->assertSame(
            'Zm9v',
            ParagonIE_Sodium_Compat::bin2base64('foo', ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE)
        );
        $this->assertSame(
            'Zm9vYg==',
            ParagonIE_Sodium_Compat::bin2base64('foob', ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL)
        );
        $this->assertSame(
            'Zm9vYg',
            ParagonIE_Sodium_Compat::bin2base64('foob', ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL_NO_PADDING)
        );
    }

    public static function paddingVectors()
    {
        $encodings = array(
            '', 'A', 'AA', 'AAA', 'AAAA', 'AAAAA', 'AAAAAA', 'AAAAAAA', 'AA=', 'AA==', 'AA===', 'AAA=', 'AAA==',
            'AAAA=', '====', 'A===', 'AA=A', 'Zg==', 'Zm8='
        );
        $token = base64_encode(str_repeat("\xa5", 32));
        $last = strlen($token) - 2;
        foreach (array('U', 'V', 'W', 'X') as $tail) {
            $candidate = $token;
            $candidate[$last] = $tail;
            $encodings[] = $candidate;
            $encodings[] = rtrim($candidate, '=');
        }
        $cases = array();
        foreach (
            array(
                ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL,
                ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL_NO_PADDING,
                ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE,
                ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE_NO_PADDING
            ) as $variant) {
            foreach ($encodings as $encoded) {
                $cases['variant ' . $variant . ': ' . $encoded] = array($encoded, $variant);
            }
        }
        return $cases;
    }

    /**
     * @dataProvider paddingVectors
     */
    public function testPaddingMatchesNative($encoded, $variant)
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

    public function testAllTwoCharacterEncodingsMatchNative()
    {
        $original = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        $urlSafe = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
        foreach (
            array(
                ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL => array($original, '=='),
                ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL_NO_PADDING => array($original, ''),
                ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE => array($urlSafe, '=='),
                ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE_NO_PADDING => array($urlSafe, '')
            ) as $variant => $providedValues2
        ) {
            list($alphabet, $padding) = $providedValues2;
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
