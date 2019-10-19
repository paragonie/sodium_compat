<?php

class UtilTest extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    public function testAbs()
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
     * @covers ParagonIE_Sodium_Compat::base642bin()
     * @covers ParagonIE_Sodium_Compat::bin2base64()
     * @throws TypeError
     * @throws Exception
     */
    public function testBase64()
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
     * @covers ParagonIE_Sodium_Core_Util::bin2hex()
     * @covers ParagonIE_Sodium_Core_Util::hex2bin()
     * @throws TypeError
     * @throws Exception
     */
    public function testBin2hex()
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
     * @covers ParagonIE_Sodium_Compat::randombytes_buf()
     * @covers ParagonIE_Sodium_Compat::randombytes_random16()
     * @covers ParagonIE_Sodium_Compat::randombytes_uniform()
     * @throws TypeError
     */
    public function testRandombytes()
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
     * @covers ParagonIE_Sodium_Core_Util::intArrayToString()
     * @covers ParagonIE_Sodium_Core_Util::stringToIntArray()
     * @throws TypeError
     */
    public function testConversion()
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
     * @covers ParagonIE_Sodium_Core_Util::hashEquals()
     * @throws SodiumException
     * @throws TypeError
     */
    public function testHashEquals()
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
     * @covers ParagonIE_Sodium_Core_Util::load_3()
     * @throws TypeError
     */
    public function testLoad3()
    {
        $this->assertSame(
            8451279,
            ParagonIE_Sodium_Core_Curve25519::load_3("\xcf\xf4\x80"),
            'Unexpected result from load_3'
        );
        $this->assertSame(
            8516815,
            ParagonIE_Sodium_Core_Curve25519::load_3("\xcf\xf4\x81"),
            'Verify endianness is correct'
        );
        $this->assertSame(
            8451280,
            ParagonIE_Sodium_Core_Curve25519::load_3("\xd0\xf4\x80"),
            'Verify endianness is correct'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Core_Util::load_4()
     * @throws TypeError
     */
    public function testLoad4()
    {
        $this->assertSame(
            8451279,
            ParagonIE_Sodium_Core_Util::load_4("\xcf\xf4\x80\x00"),
            'Unexpected result from load_4'
        );
        if (PHP_INT_SIZE === 8) {
            $this->assertSame(
                2163527424,
                ParagonIE_Sodium_Core_Util::load_4("\x00\xcf\xf4\x80"),
                'Unexpected result from load_4'
            );
        } else {
            $this->assertSame(
                -2131439872,
                ParagonIE_Sodium_Core_Util::load_4("\x00\xcf\xf4\x80"),
                'Unexpected result from load_4'
            );
        }
    }

    /**
     * @covers ParagonIE_Sodium_Core_Util::load64_le()
     * @throws SodiumException
     * @throws TypeError
     */
    public function testLoad64()
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

    /**
     * @covers ParagonIE_Sodium_Core_Util::strlen()
     */
    public function testStrlen()
    {
        $this->assertSame(4, ParagonIE_Sodium_Core_Util::strlen("\xF0\x9D\x92\xB3"));
    }

    /**
     * @covers ParagonIE_Sodium_Core_Util::strlen()
     */
    public function testSubstr()
    {
        $string = str_repeat("\xF0\x9D\x92\xB3", 4);
        $this->assertSame(ParagonIE_Sodium_Core_Util::substr($string, 0, 1), "\xF0");
        $this->assertSame(ParagonIE_Sodium_Core_Util::substr($string, 1, 1), "\x9D");
        $this->assertSame(ParagonIE_Sodium_Core_Util::substr($string, 2, 1), "\x92");
        $this->assertSame(ParagonIE_Sodium_Core_Util::substr($string, 3, 1), "\xB3");
        $this->assertSame(ParagonIE_Sodium_Core_Util::substr($string, 0, 2), "\xF0\x9D");
        $this->assertSame(ParagonIE_Sodium_Core_Util::substr($string, 2, 2), "\x92\xB3");
    }
    /**
     * @covers ParagonIE_Sodium_Core_Util::store64_le()
     */
    public function testStore64()
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
     * @covers ParagonIE_Sodium_Core_Util::mul()
     */
    public function testMul()
    {
        if (PHP_INT_SIZE === 4) {
            return;
        }
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
            $this->assertSame(
                (int) ($arg[0] * $arg[1]),
                ParagonIE_Sodium_Core_Util::mul($arg[0], $arg[1]),
                'Multiplying ' . $arg[0] . ' by ' . $arg[1] . ' failed.'
            );
        }
    }
}
