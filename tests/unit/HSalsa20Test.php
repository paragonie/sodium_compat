<?php

use PHPUnit\Framework\Attributes\BeforeClass;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(ParagonIE_Sodium_Core_HSalsa20::class)]
class HSalsa20Test extends TestCase
{
    public function testVector(): void
    {
        $key = str_repeat("\x00", 32);
        $iv = str_repeat("\x00", 16);

        $this->assertSame(
            '351f86faa3b988468a850122b65b0acece9c4826806aeee63de9c0da2bd7f91e',
            ParagonIE_Sodium_Core_Util::bin2hex(
                ParagonIE_Sodium_Core_HSalsa20::hsalsa20($iv, $key)
            ),
            'hsalsa20 with all 0s'
        );

        $iv = "\x80" . str_repeat("\x00", 15);

        $this->assertSame(
            'c541cd62360146f5140fa1c76ce1270883ff6605673d6c3e29f1d3510dfc0405',
            ParagonIE_Sodium_Core_Util::bin2hex(
                ParagonIE_Sodium_Core_HSalsa20::hsalsa20($iv, $key)
            ),
            'hsalsa20 with one nonce bitflip'
        );

        $key = "\x80" . str_repeat("\x00", 31);
        $iv = str_repeat("\x00", 16);

        $this->assertSame(
            '7e461f7c9b153c059990dd6a0a8c81acd23b7a5fad9f6844b22c97559e2723c7',
            ParagonIE_Sodium_Core_Util::bin2hex(
                ParagonIE_Sodium_Core_HSalsa20::hsalsa20($iv, $key)
            ),
            'hsalsa20 with one key bitflip'
        );
    }

    /**
     * @throws Exception
     */
    public function testWithConstant(): void
    {
        $key = random_bytes(32);
        $nonce = random_bytes(16);
        $constant = random_bytes(16);

        $output1 = ParagonIE_Sodium_Core_HSalsa20::hsalsa20($nonce, $key);
        $output2 = ParagonIE_Sodium_Core_HSalsa20::hsalsa20($nonce, $key, $constant);

        $this->assertNotSame($output1, $output2);
        $this->assertSame(32, ParagonIE_Sodium_Core_Util::strlen($output2));
    }
}
