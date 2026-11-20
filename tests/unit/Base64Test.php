<?php

/**
 * @covers ParagonIE_Sodium_Compat
 */
class Base64Test extends PHPUnit_Framework_TestCase
{
    /**
     * @before
     */
    public function before()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    public static function variants()
    {
        return array(
            array(ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL),
            array(ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE),
            array(ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL_NO_PADDING),
            array(ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE_NO_PADDING)
        );
    }

    /**
     * @dataProvider variants
     * @throws SodiumException
     */
    public function testEmpty($variant)
    {
        $this->assertSame('', ParagonIE_Sodium_Compat::base642bin('', $variant));
        $this->assertSame('', ParagonIE_Sodium_Compat::bin2base64('', $variant));
    }

    public function testEncodeInvalidVariant()
    {
        if (method_exists($this, 'expectException')) {
            $this->expectException('SodiumException');
        } else {
            $this->setExpectedException('SodiumException');
        }
        ParagonIE_Sodium_Compat::bin2base64('foo', 9999);
    }

    public function testDecodeInvalidVariant()
    {
        if (method_exists($this, 'expectException')) {
            $this->expectException('SodiumException');
        } else {
            $this->setExpectedException('SodiumException');
        }
        ParagonIE_Sodium_Compat::base642bin('foo', 9999);
    }

    /**
     * @dataProvider variants
     * @throws Exception
     */
    public function testReversible($variant)
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
    public function testBase642BinVariants()
    {
        $this->assertSame('foo', ParagonIE_Sodium_Compat::base642bin('Zm9v', ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL));
        $this->assertSame('foo', ParagonIE_Sodium_Compat::base642bin('Zm9v', ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE));
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
        $this->assertSame('foob', ParagonIE_Sodium_Compat::base642bin('Zm9vYg', ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL_NO_PADDING));
        $this->assertSame('foob', ParagonIE_Sodium_Compat::base642bin('Zm9vYg', ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE_NO_PADDING));
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
        if (method_exists($this, 'expectException')) {
            $this->expectException('SodiumException');
        } else {
            $this->setExpectedException('SodiumException', 'invalid base64 variant identifier');
        }
        if (method_exists($this, 'expectExceptionMessage')) {
            $this->expectExceptionMessage('invalid base64 variant identifier');
        }
        ParagonIE_Sodium_Compat::bin2base64('foob', 9999);
    }

    public static function trailingBitVectors()
    {
        $cases = array();
        foreach (self::variants() as $providedValues1) {
            list($variant) = $providedValues1;
            $urlSafe = in_array(
                $variant,
                array(
                    ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE,
                    ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE_NO_PADDING
                ),
                true
            );
            $noPadding = in_array(
                $variant,
                array(
                    ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL_NO_PADDING,
                    ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE_NO_PADDING
                ),
                true
            );
            $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' . ($urlSafe ? '-_' : '+/');
            foreach (array("\xff", "\xff\xff", str_repeat("\xa5", 32)) as $binary) {
                $encoded = base64_encode($binary);
                if ($urlSafe) {
                    $encoded = strtr($encoded, '+/', '-_');
                }
                if ($noPadding) {
                    $encoded = rtrim($encoded, '=');
                }
                $label = 'variant ' . $variant . ', ' . strlen($binary) . ' byte(s)';
                $cases[$label . ', canonical'] = array($encoded, $variant, $binary);
                $last = strlen(rtrim($encoded, '=')) - 1;
                $lastValue = strpos($alphabet, $encoded[$last]);
                $mask = strlen($binary) === 1 ? 15 : 3;
                for ($bits = 1; $bits <= $mask; ++$bits) {
                    $noncanonical = $encoded;
                    $noncanonical[$last] = $alphabet[$lastValue | $bits];
                    $cases[$label . ', unused bits ' . $bits] = array($noncanonical, $variant, null);
                }
            }
        }
        return $cases;
    }

    /**
     * @dataProvider trailingBitVectors
     * @throws SodiumException
     */
    public function testCanonicalTrailingBits($encoded, $variant, $expected)
    {
        if ($expected === null) {
            if (method_exists($this, 'expectException')) {
                $this->expectException('SodiumException');
            } else {
                $this->setExpectedException('SodiumException');
            }
            ParagonIE_Sodium_Compat::base642bin($encoded, $variant);
            return;
        }
        $this->assertSame($expected, ParagonIE_Sodium_Compat::base642bin($encoded, $variant));
    }

    /**
     * @dataProvider variants
     */
    public function testPaddingPolicy($variant)
    {
        $noPadding = in_array(
            $variant,
            array(
                ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL_NO_PADDING,
                ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE_NO_PADDING
            ),
            true
        );
        $valid = $noPadding ? 'AA' : 'AA==';
        $invalid = $noPadding ? 'AA==' : 'AA';
        $this->assertSame("\x00", ParagonIE_Sodium_Compat::base642bin($valid, $variant));
        if (method_exists($this, 'expectException')) {
            $this->expectException('SodiumException');
        } else {
            $this->setExpectedException('SodiumException');
        }
        ParagonIE_Sodium_Compat::base642bin($invalid, $variant);
    }

    /**
     * @dataProvider variants
     */
    public function testRejectsIncompleteQuartet($variant)
    {
        if (method_exists($this, 'expectException')) {
            $this->expectException('SodiumException');
        } else {
            $this->setExpectedException('SodiumException');
        }
        ParagonIE_Sodium_Compat::base642bin('A', $variant);
    }
}
