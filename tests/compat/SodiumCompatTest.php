<?php

/**
 * Class SodiumCompatTest
 */
class SodiumCompatTest extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        if (!extension_loaded('libsodium')) {
            $this->markTestSkipped('Libsodium is not installed');
        }
    }

    public function testCompare()
    {
        $a = random_bytes(16);
        $b = $a;
        $a[15] = 'a';

        $this->assertSame(
            \Sodium\compare($a, $b),
            ParagonIE_Sodium_Core_Util::compare($a, $b)
        );
    }

}