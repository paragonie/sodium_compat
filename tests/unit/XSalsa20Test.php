<?php

class XSalsa20Test extends PHPUnit_Framework_TestCase
{
    /**
     * @oovers ParagonIE_Sodium_Core_XSalsa20::xsalsa20()
     * @throws SodiumException
     * @throws TypeError
     */
    public function testVectors()
    {

        $key = "\x80" . str_repeat("\x00", 31);
        $iv = str_repeat("\x00", 24);

        if (PHP_INT_SIZE === 4) {
            $output = ParagonIE_Sodium_Core32_XSalsa20::xsalsa20(512, $iv, $key);
        } else {
            $output = ParagonIE_Sodium_Core_XSalsa20::xsalsa20(512, $iv, $key);
        }

        $this->assertSame(
            '93D88C085B8433B1FBAD2221FAD71807' .
            '8D96119F727D27F0547F9F3D29DE1358' .
            'F3FE3D9EEACF59E894FA76E6507F567B' .
            '4A0796DD00D8BFC736344A9906CB1F5D',
            strtoupper(
                bin2hex(
                    ParagonIE_Sodium_Core_Util::substr($output, 0, 64)
                )
            ),
            'Test vector #1 failed!'
        );

        $this->assertSame(
            '17FD2BD86D095016D8367E0DD47D3E4A' .
            '18DAE7BB24F8B5E3E9F52C4A493BE982' .
            'ECA8E89A4DEC78467E31087A1ACDA837' .
            '54BEFB273AB27EB396EB4957F7166C25',
            strtoupper(
                bin2hex(
                    ParagonIE_Sodium_Core_Util::substr($output, 192, 64)
                )
            ),
            'Test vector #1 failed!'
        );
    }
}
