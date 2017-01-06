<?php

class SipHashTest extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

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