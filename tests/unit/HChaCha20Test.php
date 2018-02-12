<?php

class HChaCha20Test extends PHPUnit_Framework_TestCase
{
    /**
     * @covers ParagonIE_Sodium_Core_HChaCha20::hChaCha20()
     */
    public function testVector()
    {
        $key = str_repeat("\x00", 32);
        $iv = str_repeat("\x00", 16);

        $this->assertSame(
            '1140704c328d1d5d0e30086cdf209dbd6a43b8f41518a11cc387b669b2ee6586',
            ParagonIE_Sodium_Core_Util::bin2hex(
                PHP_INT_SIZE === 4
                    ? ParagonIE_Sodium_Core32_HChaCha20::hChaCha20($iv, $key)
                    : ParagonIE_Sodium_Core_HChaCha20::hChaCha20($iv, $key)
            ),
            'hChaCha20 with all 0s'
        );

        $iv = "\x80" . str_repeat("\x00", 15);

        $this->assertSame(
            'ff34edeb8f338fb707f5ef4695302d9fc8b567517f9fc0983970019823266d2c',
            ParagonIE_Sodium_Core_Util::bin2hex(
                PHP_INT_SIZE === 4
                    ? ParagonIE_Sodium_Core32_HChaCha20::hChaCha20($iv, $key)
                    : ParagonIE_Sodium_Core_HChaCha20::hChaCha20($iv, $key)
            ),
            'hChaCha20 with one nonce bitflip'
        );

        $key = "\x80" . str_repeat("\x00", 31);
        $iv = str_repeat("\x00", 16);

        $this->assertSame(
            '7d266a7fd808cae4c02a0a70dcbfbcc250dae65ce3eae7fc210f54cc8f77df86',
            ParagonIE_Sodium_Core_Util::bin2hex(
                PHP_INT_SIZE === 4
                    ? ParagonIE_Sodium_Core32_HChaCha20::hChaCha20($iv, $key)
                    : ParagonIE_Sodium_Core_HChaCha20::hChaCha20($iv, $key)
            ),
            'hChaCha20 with one key bitflip'
        );
    }
}
