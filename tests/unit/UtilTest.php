<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(ParagonIE_Sodium_Core_Util::class)]
class UtilTest extends TestCase
{
    /**
     * @before
     */
    #[Before]
    public function before(): void
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    public function testAndString(): void
    {
        $x = "\x01\x02\x03\x04";
        $y = "\xff\xff\xff\xff";
        $z = "\xcc\x8a\xcc\x00";

        $this->assertSame($x, ParagonIE_Sodium_Core_Util::andStrings($x, $y));
        $this->assertSame(
            ParagonIE_Sodium_Core_Util::bin2hex($z),
            ParagonIE_Sodium_Core_Util::bin2hex(ParagonIE_Sodium_Core_Util::andStrings($y, $z))
        );
        $this->assertSame(
            '00020000',
            ParagonIE_Sodium_Core_Util::bin2hex(ParagonIE_Sodium_Core_Util::andStrings($x, $z))
        );
    }

    public function testAbs(): void
    {
        $this->assertEquals(0, ParagonIE_Sodium_Core_Util::abs(0));
        $this->assertEquals(1, ParagonIE_Sodium_Core_Util::abs(1));
        $this->assertEquals(1, ParagonIE_Sodium_Core_Util::abs(-1));
        $this->assertEquals(PHP_INT_MAX, ParagonIE_Sodium_Core_Util::abs(PHP_INT_MAX));
        $this->assertEquals(PHP_INT_MAX, ParagonIE_Sodium_Core_Util::abs(-PHP_INT_MAX));

        for ($i = 0; $i < 1000; ++$i) {
            $int = random_int(-PHP_INT_MAX, PHP_INT_MAX);
            $this->assertEquals((int) abs($int), ParagonIE_Sodium_Core_Util::abs($int));
        }
    }

    /**
     * @throws TypeError
     * @throws Exception
     */
    public function testBase64(): void
    {
        for ($i = 0; $i < 100; $i++) {
            $bin = $i === 0 ? '' : random_bytes($i);
            $b64 = base64_encode($bin);
            $b64_ = ParagonIE_Sodium_Compat::bin2base64($bin, SODIUM_BASE64_VARIANT_ORIGINAL);
            $this->assertEquals($b64, $b64_);
            $bin_ = ParagonIE_Sodium_Compat::base642bin($b64, SODIUM_BASE64_VARIANT_ORIGINAL);
            $this->assertEquals($bin, $bin_);

            $b64u = strtr(base64_encode($bin), '+/', '-_');
            $b64u_ = ParagonIE_Sodium_Compat::bin2base64($bin, SODIUM_BASE64_VARIANT_URLSAFE);
            $this->assertEquals($b64u, $b64u_);
            $binu_ = ParagonIE_Sodium_Compat::base642bin($b64u, SODIUM_BASE64_VARIANT_URLSAFE);
            $this->assertEquals($bin, $binu_);
        }

        $x = chunk_split(base64_encode(random_bytes(100)));
        ParagonIE_Sodium_Compat::base642bin($x, SODIUM_BASE64_VARIANT_ORIGINAL, "\r\n");
    }

    /**
     * @throws TypeError
     * @throws Exception
     */
    public function testBin2hex(): void
    {
        $data = random_bytes(32);
        $this->assertSame(
            bin2hex($data),
            ParagonIE_Sodium_Core_Util::bin2hex($data),
            'bin2hex should be the compatible with PHP'
        );
        $this->assertSame(
            $data,
            ParagonIE_Sodium_Core_Util::hex2bin(
                ParagonIE_Sodium_Core_Util::bin2hex($data)
            ),
            'bin2hex and hex2bin should decode a string to itself'
        );
        $this->assertSame(
            $data,
            ParagonIE_Sodium_Core_Util::hex2bin(
                bin2hex($data)
            ),
            'hex2bin should be compatible with PHP'
        );
    }

    /**
     * @throws Exception
     */
    public function testRandombytes(): void
    {
        $random = ParagonIE_Sodium_Compat::randombytes_buf(32);
        $this->assertSame(32, ParagonIE_Sodium_Core_Util::strlen($random));

        $other = ParagonIE_Sodium_Compat::randombytes_buf(32);
        $this->assertNotSame($random, $other);

        $int = ParagonIE_Sodium_Compat::randombytes_uniform(1000);
        $this->assertLessThan(1000, $int, 'Out of bounds (> 1000)');
        $this->assertGreaterThan(-1, $int, 'Out of bounds (< 0)');

        $int = ParagonIE_Sodium_Compat::randombytes_random16();
        $this->assertLessThan(65536, $int, 'Out of bounds (> 65535)');
        $this->assertGreaterThan(-1, $int, 'Out of bounds (< 0)');
    }

    /**
     * @throws TypeError
     */
    public function testConversion(): void
    {
        $sample = array(80, 97, 114, 97, 103, 111, 110);

        $this->assertSame(
            'Paragon',
            ParagonIE_Sodium_Core_Util::intArrayToString($sample)
        );

        $this->assertSame(
            $sample,
            ParagonIE_Sodium_Core_Util::stringToIntArray('Paragon')
        );
    }

    /**
     * @throws Exception
     */
    public function testHashEquals(): void
    {
        if (PHP_VERSION_ID < 50600) {
            for ($i = 0; $i < 65536; ++$i) {
                $a = random_bytes(64);
                $b = random_bytes(64);
                $this->assertFalse(
                    ParagonIE_Sodium_Core_Util::hashEquals($a, $b),
                    bin2hex($a) . ' == ' . bin2hex($b) . ' should return false.'
                );
            }
        } else {
            $this->markTestSkipped('PHP > 5.6 does not need this test');
        }
    }

    /**
     * @throws TypeError
     */
    public function testLoad3(): void
    {
        $this->assertSame(
            8451279,
            ParagonIE_Sodium_Core_Util::load_3("\xcf\xf4\x80"),
            'Unexpected result from load_3'
        );
        $this->assertSame(
            8516815,
            ParagonIE_Sodium_Core_Util::load_3("\xcf\xf4\x81"),
            'Verify endianness is correct'
        );
        $this->assertSame(
            8451280,
            ParagonIE_Sodium_Core_Util::load_3("\xd0\xf4\x80"),
            'Verify endianness is correct'
        );
    }

    /**
     * @throws TypeError
     */
    public function testLoad4(): void
    {
        $this->assertSame(
            8451279,
            ParagonIE_Sodium_Core_Util::load_4("\xcf\xf4\x80\x00"),
            'Unexpected result from load_4'
        );
        $this->assertSame(
            2163527424,
            ParagonIE_Sodium_Core_Util::load_4("\x00\xcf\xf4\x80"),
            'Unexpected result from load_4'
        );
    }

    /**
     * @throws SodiumException
     * @throws TypeError
     */
    public function testLoad64(): void
    {
        if (PHP_INT_SIZE < 8) {
            $this->markTestSkipped('Public utility test for load64_le()');
        }
        $this->assertSame(
            8451279,
            ParagonIE_Sodium_Core_Util::load64_le("\xcf\xf4\x80\x00\x00\x00\x00\x00"),
            'Unexpected result from load64_le'
        );
        $this->assertSame(
            9223372036854775807,
            ParagonIE_Sodium_Core_Util::load64_le("\xff\xff\xff\xff\xff\xff\xff\x7f"),
            'Unexpected result from load64_le'
        );
    }

    public function testStrlen(): void
    {
        $this->assertSame(4, ParagonIE_Sodium_Core_Util::strlen("\xF0\x9D\x92\xB3"));
    }

    public function testSubstr(): void
    {
        $string = str_repeat("\xF0\x9D\x92\xB3", 4);
        $this->assertSame("\xF0", ParagonIE_Sodium_Core_Util::substr($string, 0, 1));
        $this->assertSame("\x9D", ParagonIE_Sodium_Core_Util::substr($string, 1, 1));
        $this->assertSame("\x92", ParagonIE_Sodium_Core_Util::substr($string, 2, 1));
        $this->assertSame("\xB3", ParagonIE_Sodium_Core_Util::substr($string, 3, 1));
        $this->assertSame("\xF0\x9D", ParagonIE_Sodium_Core_Util::substr($string, 0, 2));
        $this->assertSame("\x92\xB3", ParagonIE_Sodium_Core_Util::substr($string, 2, 2));
        $this->assertSame("\x9D\x92\xB3", ParagonIE_Sodium_Core_Util::substr($string, 13));
    }

    public function testStore64(): void
    {
        if (PHP_INT_SIZE < 8) {
            $this->markTestSkipped('Public utility test for load64_le()');
        }
        $this->assertSame(
            bin2hex("\xcf\xf4\x80\x00\x00\x00\x00\x00"),
            bin2hex(ParagonIE_Sodium_Core_Util::store64_le(8451279)),
            'Unexpected result from store64_le'
        );
        $this->assertSame(
            bin2hex("\xff\xff\xff\xff\xff\xff\xff\x7f"),
            bin2hex(ParagonIE_Sodium_Core_Util::store64_le(9223372036854775807)),
            'Unexpected result from store64_le'
        );
    }


    /**
     * @throws Exception
     */
    public function testMul(): void
    {
        $arguments = array(
            array(1, 1),
            array(65534, 65534),
            array(65535, 65534),
            array(-65535, 65534),
            array(19, -13120145),
            array(0x7ffffffe, 1),
            array(0x1fffffff, 0x1fffffff),
            array(0x01, 0x7fffffff),
            array(0x7fffffff, 0x01),
            array(0x80808080, 0x01),
            array(0xffffffff, 0x01),
            array(0xffffffff, 0x02),
            array(0xffffffff, 0xffffffff)
        );
        for ($i = 0; $i < 100; ++$i) {
            $arguments[] = array(
                random_int(0, 0x7fffffff),
                random_int(0, 0x7fffffff)
            );
        }
        for ($i = 0; $i < 100; ++$i) {
            $arguments[] = array(
                -random_int(0, 0x7fffffff),
                -random_int(0, 0x7fffffff)
            );
        }
        for ($i = 0; $i < 100; ++$i) {
            $arguments[] = array(
                -random_int(0, 0x7fffffff),
                random_int(0, 0x7fffffff)
            );
        }
        for ($i = 0; $i < 100; ++$i) {
            $arguments[] = array(
                random_int(0, 0x7fffffff),
                -random_int(0, 0x7fffffff)
            );
        }

        foreach ($arguments as $arg) {
            $product = $arg[0] * $arg[1];
            if (is_float($product)) {
                // Int-to-float is deprecated as of 8.1; this test case is bogus
                continue;
            }
            $this->assertSame(
                (int) $product,
                ParagonIE_Sodium_Core_Util::mul($arg[0], $arg[1]),
                'Multiplying ' . $arg[0] . ' by ' . $arg[1] . ' failed.'
            );
        }
    }

    public function testCompare(): void
    {
        $this->assertSame(0, ParagonIE_Sodium_Core_Util::compare('abcd', 'abcd'));
        $this->assertSame(-1, ParagonIE_Sodium_Core_Util::compare('abcc', 'abcd'));
        $this->assertSame(1, ParagonIE_Sodium_Core_Util::compare('abdd', 'abcd'));
        $this->assertSame(-1, ParagonIE_Sodium_Core_Util::compare('abcd', 'abce'));
        $this->assertSame(1, ParagonIE_Sodium_Core_Util::compare('abcd', 'abcc'));
    }

    public function testChrToInt(): void
    {
        $this->assertSame(65, ParagonIE_Sodium_Core_Util::chrToInt('A'));
        $this->assertSame(97, ParagonIE_Sodium_Core_Util::chrToInt('a'));

        try {
            ParagonIE_Sodium_Core_Util::chrToInt('ab');
            $this->fail('Should have thrown an exception');
        } catch (SodiumException $ex) {
            $this->assertInstanceOf(SodiumException::class, $ex);
        }
    }

    public function testIntToChr(): void
    {
        $this->assertSame('A', ParagonIE_Sodium_Core_Util::intToChr(65));
        $this->assertSame('a', ParagonIE_Sodium_Core_Util::intToChr(97));
    }

    public function testStore32_le(): void
    {
        $this->assertSame(pack('V', 1), ParagonIE_Sodium_Core_Util::store32_le(1));
        $this->assertSame(pack('V', -1), ParagonIE_Sodium_Core_Util::store32_le(-1));
    }

    /**
     * @throws Exception
     */
    public function testXorStrings(): void
    {
        $a = random_bytes(32);
        $b = random_bytes(32);
        $this->assertSame($a ^ $b, ParagonIE_Sodium_Core_Util::xorStrings($a, $b));
    }

    /**
     * @throws Exception
     */
    public function testMemcmp(): void
    {
        $a = random_bytes(32);
        $b = random_bytes(32);
        $this->assertSame(0, ParagonIE_Sodium_Core_Util::memcmp($a, $a));
        $this->assertNotEquals(0, ParagonIE_Sodium_Core_Util::memcmp($a, $b));
    }

    public function testRandombytesUniformEdgeCases(): void
    {
        $this->assertSame(0, ParagonIE_Sodium_Compat::randombytes_uniform(1));
        for ($i = 0; $i < 128; ++$i) {
            $val = ParagonIE_Sodium_Compat::randombytes_uniform(2);
            $this->assertGreaterThan(-1, $val);
            $this->assertLessThan(2, $val);
        }
    }

    /**
     * @throws Exception
     */
    public function testVerify16(): void
    {
        $a = random_bytes(16);
        $b = random_bytes(16);
        $this->assertTrue(ParagonIE_Sodium_Core_Util::verify_16($a, $a));
        $this->assertFalse(ParagonIE_Sodium_Core_Util::verify_16($a, $b));
    }

    /**
     * @throws Exception
     * @throws SodiumException
     */
    public function testVerify32(): void
    {
        $a = random_bytes(32);
        $b = random_bytes(32);
        $this->assertTrue(ParagonIE_Sodium_Core_Util::verify_32($a, $a));
        $this->assertFalse(ParagonIE_Sodium_Core_Util::verify_32($a, $b));
    }

    /**
     * @throws Exception
     */
    public function testHashEqualsCoverage(): void
    {
        $a = random_bytes(32);
        $b = random_bytes(32);
        $this->assertTrue(ParagonIE_Sodium_Core_Util::hashEquals($a, $a));
        $this->assertFalse(ParagonIE_Sodium_Core_Util::hashEquals($a, $b));
    }

    /**
     * @throws SodiumException
     */
    public function testAdd(): void
    {
        $a = "\x01\x00\x00\x00";
        $b = "\x01\x00\x00\x00";
        ParagonIE_Sodium_Compat::add($a, $b);
        $this->assertSame("\x02\x00\x00\x00", $a);

        $a = "\xff\xff\xff\xff";
        ParagonIE_Sodium_Compat::add($a, $b);
        $this->assertSame("\x00\x00\x00\x00", $a);

        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('values must have the same length');
        ParagonIE_Sodium_Compat::add($a, 'f');
    }

    /**
     * @throws SodiumException
     */
    public function testAddBadLength(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('values must have the same length');
        $str = '';
        ParagonIE_Sodium_Compat::add($str, 'ffff');
    }

    /**
     * @throws SodiumException
     */
    public function testSub(): void
    {
        $a = "\x02\x00\x00\x00";
        $b = "\x01\x00\x00\x00";
        ParagonIE_Sodium_Compat::sub($a, $b);
        $this->assertSame("\x01\x00\x00\x00", $a);

        $a = "\x00\x00\x00\x00";
        ParagonIE_Sodium_Compat::sub($a, $b);
        $this->assertSame("\xff\xff\xff\xff", $a);
    }

    /**
     * @throws SodiumException
     */
    public function testIncrement(): void
    {
        $a = "\x00\x00\x00\x00";
        ParagonIE_Sodium_Compat::increment($a);
        $this->assertSame("\x01\x00\x00\x00", $a);

        $a = "\xff\xff\xff\xff";
        ParagonIE_Sodium_Compat::increment($a);
        $this->assertSame("\x00\x00\x00\x00", $a);
    }

    /**
     * @throws SodiumException
     */
    public function testIsZero(): void
    {
        $a = str_repeat("\x00", 32);
        $this->assertTrue(ParagonIE_Sodium_Compat::is_zero($a));

        $a = str_repeat("\x00", 31) . "\x01";
        $this->assertFalse(ParagonIE_Sodium_Compat::is_zero($a));
    }

    /**
     * @throws SodiumException
     */
    public function testPadUnpad(): void
    {
        $message = 'test message';
        $padded = ParagonIE_Sodium_Compat::pad($message, 16);
        $this->assertSame(16, ParagonIE_Sodium_Core_Util::strlen($padded));
        $unpadded = ParagonIE_Sodium_Compat::unpad($padded, 16);
        $this->assertSame($message, $unpadded);

        $message = 'another test message';
        $padded = ParagonIE_Sodium_Compat::pad($message, 32);
        $this->assertSame(32, ParagonIE_Sodium_Core_Util::strlen($padded));
        $unpadded = ParagonIE_Sodium_Compat::unpad($padded, 32);
        $this->assertSame($message, $unpadded);
    }

    /**
     * @throws SodiumException
     */
    public function testCompatCompare(): void
    {
        $this->assertSame(0, ParagonIE_Sodium_Compat::compare('abcd', 'abcd'));
        $this->assertSame(-1, ParagonIE_Sodium_Compat::compare('abcc', 'abcd'));
        $this->assertSame(1, ParagonIE_Sodium_Compat::compare('abdd', 'abcd'));
        $this->assertSame(-1, ParagonIE_Sodium_Compat::compare('abcd', 'abce'));
        $this->assertSame(1, ParagonIE_Sodium_Compat::compare('abcd', 'abcc'));
    }

    /**
     * @throws Exception
     * @throws SodiumException
     * @throws TypeError
     */
    public function testCompatMemcmp(): void
    {
        $a = random_bytes(32);
        $b = random_bytes(32);
        $this->assertSame(0, ParagonIE_Sodium_Compat::memcmp($a, $a));
        $this->assertNotEquals(0, ParagonIE_Sodium_Compat::memcmp($a, $b));
    }
}
