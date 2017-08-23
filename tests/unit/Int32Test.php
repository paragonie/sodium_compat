<?php

class Int32Test extends PHPUnit_Framework_TestCase
{
    public function testConversion()
    {
        $binary = ParagonIE_Sodium_Compat::hex2bin("12345678");
        $from = ParagonIE_Sodium_Core32_Int32::fromString($binary);
        $this->assertSame(
            array(0x1234, 0x5678),
            $from->limbs,
            'fromString()'
        );
        $this->assertSame(
            bin2hex($binary),
            bin2hex((string) $from)
        );
    }

    /**
     * @covers ParagonIE_Sodium_Core32_Int32::addInt32()
     */
    public function testAddInt32()
    {
        $one = new ParagonIE_Sodium_Core32_Int32(
            array(0x0000, 0x0001)
        );

        $this->assertSame(
            array(0x0000, 0x0004),
            $one->addInt32(
                new ParagonIE_Sodium_Core32_Int32(
                    array(0x0000, 0x0003)
                )
            )->limbs,
            'Adding 1 to 3 should yield 4'
        );
        $this->assertSame(
            array(0x0001, 0x0000),
            $one->addInt32(
                new ParagonIE_Sodium_Core32_Int32(
                    array(0x0000, 0xffff)
                )
            )->limbs,
            'Adding 1 to 0x0000fffff should yield 0x000100000'
        );

        $this->assertSame(
            array(0x0000, 0x0000),
            $one->addInt32(
                new ParagonIE_Sodium_Core32_Int32(
                    array(0xffff, 0xffff)
                )
            )->limbs,
            'Adding 1 to 0xfffffffff should yield 0x000000000'
        );

        // Random values
        $a = random_int(0, (1 << 15) - 1) << 16;
        $b = random_int(0, (1 << 16) - 1);
        $c = random_int(0, (1 << 15) - 1) << 16;
        $d = random_int(0, (1 << 16) - 1);

        $a32 = new ParagonIE_Sodium_Core32_Int32(array($a, $b));
        $b32 = new ParagonIE_Sodium_Core32_Int32(array($c, $d));
        $c32 = $a32->addInt32($b32);

        $this->assertSame(
            array(
                ($a + $c + (($b + $d) >> 16)) & 0xffff,
                ($b + $d) & 0xffff
            ),
            $c32->limbs
        );
    }

    /**
     * @covers ParagonIE_Sodium_Core32_Int32::addInt32()
     */
    public function testAddInt()
    {
        $one = new ParagonIE_Sodium_Core32_Int32(
            array(0x0000, 0x0001)
        );

        $this->assertSame(
            array(0x0000, 0x0004),
            $one->addInt(3)->limbs,
            'Adding 1 to 3 should yield 4'
        );

        $big = new ParagonIE_Sodium_Core32_Int32(
            array(0x7fff, 0xffff)
        );
        $this->assertSame(
            array(0x8000, 0x0002),
            $big->addInt(3)->limbs
        );

        $vbig = new ParagonIE_Sodium_Core32_Int32(
            array(0xffff, 0xffff)
        );
        $this->assertSame(
            array(0x0000, 0x0000),
            $vbig->addInt(1)->limbs
        );
        $this->assertSame(
            array(0x0000, 0x0001),
            $vbig->addInt(2)->limbs
        );
    }

    /**
     * @covers ParagonIE_Sodium_Core32_Int32::rotateLeft()
     */
    public function testRotateLeft()
    {
        $begin = new ParagonIE_Sodium_Core32_Int32(
            array(0x1234, 0x5678)
        );

        $this->assertSame(
            array(0x2468, 0xacf0),
            $begin->rotateLeft(1)->limbs
        );
        $this->assertSame(
            array(0x2345, 0x6781),
            $begin->rotateLeft(4)->limbs
        );
        $this->assertSame(
            array(0x5678, 0x1234),
            $begin->rotateLeft(16)->limbs
        );
        $this->assertSame(
            array(0x1234, 0x5678),
            $begin->rotateLeft(32)->limbs
        );
    }
}
