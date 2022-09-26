<?php

class HexTest extends PHPUnit_Framework_TestCase
{
    public function hexProvider()
    {
        return array(
            array('DEADBEEF', '', "\xde\xad\xbe\xef", false),
            array('DeAdBeeF', '', "\xde\xad\xbe\xef", false),
            array("De\nAdBe\neF", "\n", "\xde\xad\xbe\xef", false),
            array("De\nAdBe eF", "\n", "\xde\xad\xbe\xef", true),
            array("De\nAdBe eF", "\n ", "\xde\xad\xbe\xef", false),
            array("De AdBe eF", " ", "\xde\xad\xbe\xef", false),
        );
    }

    /**
     * @dataProvider hexProvider
     */
    public function testHex2Bin($hex, $ignore, $binary, $fail)
    {
        try {
            $decoded = ParagonIE_Sodium_Compat::hex2bin($hex, $ignore);
            $this->assertFalse($fail, 'This should have failed but did not!');
            $this->assertSame($binary, $decoded, 'Binary mismatch');
        } catch (RangeException $ex) {
            $this->assertTrue($fail, 'An unexpected hex2bin failure occurred');
        } catch (SodiumException $ex) {
            $this->assertTrue($fail, 'An unexpected hex2bin failure occurred');
        }
    }
}
