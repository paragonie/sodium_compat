<?php

class HSalsa20Test extends PHPUnit_Framework_TestCase
{
    /**
     * @covers ParagonIE_Sodium_Core_Hsalsa20::hsalsa20()
     */
    public function testVector()
    {
        $key = str_repeat("\x00", 32);
        $iv = str_repeat("\x00", 16);

        $this->assertSame(
            '351f86faa3b988468a850122b65b0acece9c4826806aeee63de9c0da2bd7f91e',
            ParagonIE_Sodium_Core_Util::bin2hex(
                PHP_INT_SIZE === 4
                    ? ParagonIE_Sodium_Core32_Hsalsa20::hsalsa20($iv, $key)
                    : ParagonIE_Sodium_Core_Hsalsa20::hsalsa20($iv, $key)
            ),
            'hsalsa20 with all 0s'
        );

        $iv = "\x80" . str_repeat("\x00", 15);

        $this->assertSame(
            'c541cd62360146f5140fa1c76ce1270883ff6605673d6c3e29f1d3510dfc0405',
            ParagonIE_Sodium_Core_Util::bin2hex(
                PHP_INT_SIZE === 4
                    ? ParagonIE_Sodium_Core32_Hsalsa20::hsalsa20($iv, $key)
                    : ParagonIE_Sodium_Core_Hsalsa20::hsalsa20($iv, $key)
            ),
            'hsalsa20 with one nonce bitflip'
        );

        $key = "\x80" . str_repeat("\x00", 31);
        $iv = str_repeat("\x00", 16);

        $this->assertSame(
            '7e461f7c9b153c059990dd6a0a8c81acd23b7a5fad9f6844b22c97559e2723c7',
            ParagonIE_Sodium_Core_Util::bin2hex(
                PHP_INT_SIZE === 4
                    ? ParagonIE_Sodium_Core32_Hsalsa20::hsalsa20($iv, $key)
                    : ParagonIE_Sodium_Core_Hsalsa20::hsalsa20($iv, $key)
            ),
            'hsalsa20 with one key bitflip'
        );
    }
}
