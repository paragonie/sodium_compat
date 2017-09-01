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
            $this->markTestSkipped('Test is not relevant to 32-bit');
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
        if (PHP_INT_SIZE === 4) {
            $this->markTestSkipped('Test is not relevant to 32-bit');
            return;
        }
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
            'rotl_64 by 95 (reduce to 31)'
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

    public function testSipRound()
    {
        if (PHP_INT_SIZE === 8) {
            $v = array(
                0x736f6d65, // 0
                0x70736575, // 1
                0x646f7261, // 2
                0x6e646f6d, // 3
                0x6c796765, // 4
                0x6e657261, // 5
                0x74656462, // 6
                0x79746573  // 7
            );
            $v = ParagonIE_Sodium_Core_SipHash::sipRound($v);
            $result = array(
                ParagonIE_Sodium_Core_Util::bin2hex(
                    ParagonIE_Sodium_Core_Util::store32_le($v[1]) .
                    ParagonIE_Sodium_Core_Util::store32_le($v[0])
                ),
                ParagonIE_Sodium_Core_Util::bin2hex(
                    ParagonIE_Sodium_Core_Util::store32_le($v[3]) .
                    ParagonIE_Sodium_Core_Util::store32_le($v[2])
                ),
                ParagonIE_Sodium_Core_Util::bin2hex(
                    ParagonIE_Sodium_Core_Util::store32_le($v[5]) .
                    ParagonIE_Sodium_Core_Util::store32_le($v[4])
                ),
                ParagonIE_Sodium_Core_Util::bin2hex(
                    ParagonIE_Sodium_Core_Util::store32_le($v[7]) .
                    ParagonIE_Sodium_Core_Util::store32_le($v[6])
                )
            );
        } else {
            $v = array(
                new ParagonIE_Sodium_Core32_Int64(
                    array(0x736f, 0x6d65, 0x7073, 0x6575)
                ),
                new ParagonIE_Sodium_Core32_Int64(
                    array(0x646f, 0x7261, 0x6e64, 0x6f6d)
                ),
                new ParagonIE_Sodium_Core32_Int64(
                    array(0x6c79, 0x6765, 0x6e65, 0x7261)
                ),
                new ParagonIE_Sodium_Core32_Int64(
                    array(0x7465, 0x6462, 0x7974, 0x6573)
                )
            );
            /**
             * @var array<int, ParagonIE_Sodium_Core32_Int64> $step
             */
            $step = ParagonIE_Sodium_Core32_SipHash::sipRound($v);
            if (!($step[0] instanceof ParagonIE_Sodium_Core32_Int64)) {
                $this->fail('Type Error');
            }
            if (!($step[1] instanceof ParagonIE_Sodium_Core32_Int64)) {
                $this->fail('Type Error');
            }
            if (!($step[2] instanceof ParagonIE_Sodium_Core32_Int64)) {
                $this->fail('Type Error');
            }
            if (!($step[3] instanceof ParagonIE_Sodium_Core32_Int64)) {
                $this->fail('Type Error');
            }
            $result = array(
                ParagonIE_Sodium_Core_Util::bin2hex($step[0]->toReverseString()),
                ParagonIE_Sodium_Core_Util::bin2hex($step[1]->toReverseString()),
                ParagonIE_Sodium_Core_Util::bin2hex($step[2]->toReverseString()),
                ParagonIE_Sodium_Core_Util::bin2hex($step[3]->toReverseString())
            );
        }

        $this->assertEquals(
            array(
                '7783895a96879463',
                '6623cacba61b65fe',
                'd2bd711a4350143b',
                'e114b92cc2d2e435'
            ),
            $result
        );
    }

    /**
     * @covers ParagonIE_Sodium_Core_SipHash::sipHash24()
     */
    public function testEvenBlock()
    {
        $message = str_repeat("\xff", 32);
        $key = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10";

        $this->assertSame(
            '7f965c8b580df016',
            ParagonIE_Sodium_Core_Util::bin2hex(
                PHP_INT_SIZE === 4
                    ? ParagonIE_Sodium_Core32_SipHash::sipHash24($message, $key)
                    : ParagonIE_Sodium_Core_SipHash::sipHash24($message, $key)
            )
        );
    }

    /**
     * @covers ParagonIE_Sodium_Core_SipHash::sipHash24()
     */
    public function testCryptoShorthash()
    {
        $message = 'this is just a test message';
        $key = str_repeat("\x80", 16);

        $this->assertSame(
            '3f188259b01151a7',
            ParagonIE_Sodium_Core_Util::bin2hex(
                PHP_INT_SIZE === 4
                    ? ParagonIE_Sodium_Core32_SipHash::sipHash24($message, $key)
                    : ParagonIE_Sodium_Core_SipHash::sipHash24($message, $key)
            )
        );
    }
}
