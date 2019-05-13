<?php

class CompatTest extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    public function testIncrement()
    {
        $string = "\x00\x00\x00\x00\x00\x00\x00\x00";

        ParagonIE_Sodium_Compat::increment($string);
        $this->assertSame("0100000000000000", ParagonIE_Sodium_Core_Util::bin2hex($string));

        ParagonIE_Sodium_Compat::increment($string);
        $this->assertSame("0200000000000000", ParagonIE_Sodium_Core_Util::bin2hex($string));

        $string = "\xff\xff\x01\x20";
        ParagonIE_Sodium_Compat::increment($string);
        $this->assertSame("00000220", ParagonIE_Sodium_Core_Util::bin2hex($string));
    }

    public function testRuntimeSpeed()
    {
        if (ParagonIE_Sodium_Compat::polyfill_is_fast()) {
            return $this->markTestSkipped('Polyfill is fast, no need to test this.');
        }
        $this->assertTrue(ParagonIE_Sodium_Compat::runtime_speed_test(100, 10));
    }
}
