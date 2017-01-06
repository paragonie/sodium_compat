<?php

class SipHashTest extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @covers ParagonIE_Sodium_Core_SipHash::add()
     */
    public function testAdd()
    {
        if (PHP_INT_SIZE === 4) {
            $this->markTestSkipped('Test should be performed on a 64-bit OS');
            return;
        }

        $vectors = array(
            array(
                0x0123456789abcdef,
                0x456789abcdef0123,
                0x468acf13579acf12
            ),
            array(
                0x0000000100000000,
                0x0000000000000100,
                0x0000000100000100
            ),
            array(
                0x0000000100000000,
                0x0000000000000100,
                0x0000000100000100
            ),
            array(
                0x0fffffffffffffff,
                0x0000000000000001,
                0x1000000000000000
            )
        );
        foreach ($vectors as $v) {
            list($a, $b, $c) = $v;
            # $this->assertSame($c, PHP_INT_MAX & ($a + $b));

            $sA = array(
                $a >> 32,
                $a & 0xffffffff
            );
            $sB = array(
                $b >> 32,
                $b & 0xffffffff
            );
            $sC = array(
                ($c >> 32) & 0xffffffff,
                $c & 0xffffffff
            );
            $this->assertSame(
                $sC,
                ParagonIE_Sodium_Core_SipHash::add($sA, $sB)
            );
        }
    }

    /**
     * @covers ParagonIE_Sodium_Core_SipHash::rotl_64()
     */
    public function testRotl64()
    {
        $this->assertSame(
            array(0x00010000, 0x00000000),
            ParagonIE_Sodium_Core_SipHash::rotl_64(0x00000001, 0x00000000, 16),
            'rotl_64 by 16'
        );
        $this->assertSame(
            array(0x80000000, 0x00000000),
            ParagonIE_Sodium_Core_SipHash::rotl_64(0x00000001, 0x00000000, 31),
            'rotl_64 by 31'
        );
        $this->assertSame(
            array(0x80000000, 0x00000000),
            ParagonIE_Sodium_Core_SipHash::rotl_64(0x00000001, 0x00000000, 95),
            'rotl_64 by 95'
        );
        $this->assertSame(
            array(0x00000000, 0x00000001),
            ParagonIE_Sodium_Core_SipHash::rotl_64(0x00000001, 0x00000000, 32),
            'rotl_64 by 32'
        );
        $this->assertSame(
            array(0x00000000, 0x00000008),
            ParagonIE_Sodium_Core_SipHash::rotl_64(0x00000001, 0x00000000, 35),
            'rotl_64 by 35'
        );
        $this->assertSame(
            array(0x00000000, 0x80000000),
            ParagonIE_Sodium_Core_SipHash::rotl_64(0x00000001, 0x00000000, 63),
            'rotl_64 by 63'
        );
        $this->assertSame(
            array(0x00000001, 0x00000000),
            ParagonIE_Sodium_Core_SipHash::rotl_64(0x00000001, 0x00000000, 64),
            'rotl_64 by 64'
        );
        $this->assertSame(
            array(0x7DDF575A, 0x3BD5BD5B),
            ParagonIE_Sodium_Core_SipHash::rotl_64(0xDEADBEEF, 0xABAD1DEA, 17),
            'rotl_64 by 64'
        );
    }

    /**
     *
     */
    public function testCryptoShorthash()
    {
        $message = 'this is just a test message';
        $key = str_repeat("\x80", 16);

        $this->assertSame(
            '3f188259b01151a7',
            bin2hex(ParagonIE_Sodium_Compat::crypto_shorthash($message, $key))
        );
    }
}