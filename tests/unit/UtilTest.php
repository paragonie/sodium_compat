<?php

class UtilTest extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

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
    }

    public function testRandombytes()
    {
        $random = ParagonIE_Sodium_Compat::randombytes_buf(32);
        $this->assertSame(32, ParagonIE_Sodium_Core_Util::strlen($random));

        $other = ParagonIE_Sodium_Compat::randombytes_buf(32);
        $this->assertNotSame($random, $other);

        $int = ParagonIE_Sodium_Compat::randombytes_uniform(1000);
        $this->assertLessThan(1000, $int, 'Out of bounds (> 1000)');
        $this->assertGreaterThan(0, $int, 'Out of bounds (< 0)');
    }

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
}
