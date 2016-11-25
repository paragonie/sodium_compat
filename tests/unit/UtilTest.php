<?php

class UtilTest extends PHPUnit_Framework_TestCase
{
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
}
