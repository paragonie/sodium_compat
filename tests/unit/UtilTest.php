<?php

class UtilTest extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @covers ParagonIE_Sodium_Core_Util::bin2hex()
     * @covers ParagonIE_Sodium_Core_Util::hex2bin()
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
     */
    public function testRandombytes()
    {
        $random = ParagonIE_Sodium_Compat::randombytes_buf(32);
        $this->assertSame(32, ParagonIE_Sodium_Core_Util::strlen($random));

        $other = ParagonIE_Sodium_Compat::randombytes_buf(32);
        $this->assertNotSame($random, $other);

        $int = ParagonIE_Sodium_Compat::randombytes_uniform(1000);
        $this->assertLessThan(1000, $int, 'Out of bounds (> 1000)');
        $this->assertGreaterThan(0, $int, 'Out of bounds (< 0)');

        $int = ParagonIE_Sodium_Compat::randombytes_random16();
        $this->assertLessThan(65536, $int, 'Out of bounds (> 65535)');
        $this->assertGreaterThan(0, $int, 'Out of bounds (< 0)');
    }

    /**
     * @covers ParagonIE_Sodium_Core_Util::intArrayToString()
     * @covers ParagonIE_Sodium_Core_Util::stringToIntArray()
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
     * @covers ParagonIE_Sodium_Core_Util::load_3()
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
     * @covers ParagonIE_Sodium_Core_Util::load_3()
     */
    public function testLoad4()
    {
        $this->assertSame(
            8451279,
            ParagonIE_Sodium_Core_Curve25519::load_4("\xcf\xf4\x80\x00"),
            'Unexpected result from load_4'
        );
        $this->assertSame(
            2163527424,
            ParagonIE_Sodium_Core_Curve25519::load_4("\x00\xcf\xf4\x80"),
            'Unexpected result from load_4'
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
        $string = \str_repeat("\xF0\x9D\x92\xB3", 4);
        $this->assertSame(ParagonIE_Sodium_Core_Util::substr($string, 0, 1), "\xF0");
        $this->assertSame(ParagonIE_Sodium_Core_Util::substr($string, 1, 1), "\x9D");
        $this->assertSame(ParagonIE_Sodium_Core_Util::substr($string, 2, 1), "\x92");
        $this->assertSame(ParagonIE_Sodium_Core_Util::substr($string, 3, 1), "\xB3");
        $this->assertSame(ParagonIE_Sodium_Core_Util::substr($string, 0, 2), "\xF0\x9D");
        $this->assertSame(ParagonIE_Sodium_Core_Util::substr($string, 2, 2), "\x92\xB3");
    }

    /**
     * @covers ParagonIE_Sodium_Core_Util::mul()
     */
    public function testMul()
    {
        $arguments = array(
            array(1, 1),
            array(65534, 65534),
            array(65535, 65534),
            array(0x7ffffffe, 1),
            array(0x1fffffff, 0x1fffffff),
            array(0x01, 0x7fffffff),
            array(0x7fffffff, 0x01),
            array(0xffffffff, 0x01),
            array(0xffffffff, 0x02),
            array(0xffffffff, 0xffffffff)
        );
        foreach ($arguments as $arg) {
            $this->assertSame(
                (int) ($arg[0] * $arg[1]),
                ParagonIE_Sodium_Core_Util::mul($arg[0], $arg[1]),
                'Multiplying ' . $arg[0] . ' by ' . $arg[1] . ' failed.'
            );
        }
    }
}
