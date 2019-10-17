<?php

class Salsa20Test extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @covers ParagonIE_Sodium_Core_Salsa20::rotate()
     */
    public function testRotate()
    {
        if (PHP_INT_SIZE === 4) {
            return;
        }
        $this->assertEquals(
            0x00001000,
            ParagonIE_Sodium_Core_Salsa20::rotate(0x00000001, 12),
            'Left rotate by 12'
        );

        $this->assertEquals(
            0x00002000,
            ParagonIE_Sodium_Core_Salsa20::rotate(0x00000001, 13),
            'Left rotate by 13'
        );
        $this->assertEquals(
            0x10000000,
            ParagonIE_Sodium_Core_Salsa20::rotate(0x00000001, 28),
            'Left rotate by 28'
        );
        $this->assertEquals(
            0x80000000,
            ParagonIE_Sodium_Core_Salsa20::rotate(0x00000001, 31),
            'Left rotate by 31'
        );
        $this->assertEquals(
            0x00000001,
            ParagonIE_Sodium_Core_Salsa20::rotate(0x00000001, 32),
            'Left rotate by 32'
        );

        $this->assertEquals(
            0xf0001000,
            ParagonIE_Sodium_Core_Salsa20::rotate(0x000f0001, 12),
            'Left rotate by 12'
        );

        $this->assertEquals(
            0xe0002001,
            ParagonIE_Sodium_Core_Salsa20::rotate(0x000f0001, 13),
            'Left rotate by 13'
        );

        $this->assertEquals(
            0xc0004003,
            ParagonIE_Sodium_Core_Salsa20::rotate(0x000f0001, 14),
            'Left rotate by 14'
        );

        $this->assertEquals(
            0x80008007,
            ParagonIE_Sodium_Core_Salsa20::rotate(0x000f0001, 15),
            'Left rotate by 15'
        );

        $this->assertEquals(
            0x0001000f,
            ParagonIE_Sodium_Core_Salsa20::rotate(0x000f0001, 16),
            'Left rotate by 16'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Core_Salsa20::salsa20()
     */
    public function testVectors()
    {
        $key = "\x80" . str_repeat("\x00", 31);
        $iv = str_repeat("\x00", 8);

        if (PHP_INT_SIZE === 4) {
            $output = ParagonIE_Sodium_Core32_Salsa20::salsa20(512, $iv, $key);
        } else {
            $output = ParagonIE_Sodium_Core_Salsa20::salsa20(512, $iv, $key);
        }

        $this->assertSame(
            'E3BE8FDD8BECA2E3EA8EF9475B29A6E7' .
            '003951E1097A5C38D23B7A5FAD9F6844' .
            'B22C97559E2723C7CBBD3FE4FC8D9A07' .
            '44652A83E72A9C461876AF4D7EF1A117',
            strtoupper(
                bin2hex(
                    ParagonIE_Sodium_Core_Util::substr($output, 0, 64)
                )
            ),
            'Test vector #1 failed!'
        );

        $this->assertSame(
            '57BE81F47B17D9AE7C4FF15429A73E10' .
            'ACF250ED3A90A93C711308A74C6216A9' .
            'ED84CD126DA7F28E8ABF8BB63517E1CA' .
            '98E712F4FB2E1A6AED9FDC73291FAA17',
            strtoupper(
                bin2hex(
                    ParagonIE_Sodium_Core_Util::substr($output, 192, 64)
                )
            ),
            'Test vector #1 failed!'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Core_Salsa20::core_salsa20()
     */
    public function testCoreSalsa20()
    {
        $key = random_bytes(32);
        $iv = random_bytes(8);
        if (PHP_INT_SIZE === 4) {
            $outA = ParagonIE_Sodium_Core32_Salsa20::salsa20(192, $iv, $key);
            $outB = ParagonIE_Sodium_Core32_Salsa20::core_salsa20($iv . str_repeat("\x00", 8), $key);
            $outC = ParagonIE_Sodium_Core32_Salsa20::core_salsa20($iv . "\x01" . str_repeat("\x00", 7), $key);
            $outD = ParagonIE_Sodium_Core32_Salsa20::core_salsa20($iv . "\x02" . str_repeat("\x00", 7), $key);
        } else {
            $outA = ParagonIE_Sodium_Core_Salsa20::salsa20(192, $iv, $key);
            $outB = ParagonIE_Sodium_Core_Salsa20::core_salsa20($iv . str_repeat("\x00", 8), $key);
            $outC = ParagonIE_Sodium_Core_Salsa20::core_salsa20($iv . "\x01" . str_repeat("\x00", 7), $key);
            $outD = ParagonIE_Sodium_Core_Salsa20::core_salsa20($iv . "\x02" . str_repeat("\x00", 7), $key);
        }

        // First block
        $this->assertSame(
            bin2hex(
                ParagonIE_Sodium_Core_Util::substr($outA, 0, 64)
            ),
            bin2hex($outB)
        );

        // Second block
        $this->assertSame(
            bin2hex(
                ParagonIE_Sodium_Core_Util::substr($outA, 64, 64)
            ),
            bin2hex($outC)
        );

        // Third block
        $this->assertSame(
            bin2hex(
                ParagonIE_Sodium_Core_Util::substr($outA, 128, 64)
            ),
            bin2hex($outD)
        );
    }
}
