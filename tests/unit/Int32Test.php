<?php

class Int32Test extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        if (PHP_INT_SIZE === 8) {
            $this->markTestSkipped('Only relevant to 32-bit platforms.');
        }
    }

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
     * @covers ParagonIE_Sodium_Core32_Int32::addInt()
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

        $this->assertSame(1, $vbig->addInt(1)->overflow);
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

    public function testMask()
    {
        $begin = new ParagonIE_Sodium_Core32_Int32(
            array(0x1234, 0x5678)
        );
        $this->assertSame(
            array(0x0000, 0x5678),
            $begin->mask(0xffff)->limbs
        );
        $this->assertSame(
            array(0x1234, 0x0000),
            $begin->mask(0xffff0000)->limbs
        );

    }

    /**
     * @covers ParagonIE_Sodium_Core32_Int32::mulInt()
     * @covers ParagonIE_Sodium_Core32_Int32::mulInt32()
     */
    public function testMult()
    {
        $begin = new ParagonIE_Sodium_Core32_Int32(
            array(0x1234, 0x5678)
        );

        $this->assertSame(
            array(0x2468, 0xacf0),
            $begin->mulInt(2)->limbs
        );
        $this->assertSame(
            array(0x48d1, 0x59e0),
            $begin->mulInt(4)->limbs
        );
        $this->assertSame(
            array(0x5b05, 0xb058),
            $begin->mulInt(5)->limbs
        );

        $this->assertSame(
            array(0x48d1, 0x59e0),
            $begin->mulInt32(new ParagonIE_Sodium_Core32_Int32(array(0, 4)))->limbs
        );

        $one = new ParagonIE_Sodium_Core32_Int32(array(0, 1));
        $this->assertSame(
            array(0, 5),
            $one->mulInt(5)->limbs
        );
        $two = new ParagonIE_Sodium_Core32_Int32(array(0, 2));
        $this->assertSame(
            array(0, 10),
            $two->mulInt(5)->limbs
        );

        $baseSmall = random_int(1, 65536);
        $base = new ParagonIE_Sodium_Core32_Int32(array(0, $baseSmall));
        for ($i = 0; $i < 1024; ++$i) {
            $value = random_int(1, 65536);
            $result = ($baseSmall * $value);
            $expected = array(
                ($result >> 16) & 0xffff,
                $result & 0xffff
            );

            $this->assertSame(
                $expected,
                $base->mulInt($value)->limbs,
                $baseSmall . ' x ' . $value . ' = ' . $result
            );
        }
    }

    public function testShift()
    {
        $begin = new ParagonIE_Sodium_Core32_Int32(
            array(0x1234, 0x5678)
        );

        $this->assertSame(
            array(0x2468, 0xacf0),
            $begin->shiftLeft(1)->limbs
        );

        $this->assertSame(
            array(0x0000, 0x1234),
            $begin->shiftRight(16)->limbs
        );
    }

    /**
     * @covers ParagonIE_Sodium_Core32_Int32::subInt()
     */
    public function testSubInt()
    {
        $four = new ParagonIE_Sodium_Core32_Int32(
            array(0x0000, 0x0004)
        );

        $this->assertSame(
            array(0x0000, 0x0001),
            $four->subInt(3)->limbs,
            '4 - 3 = 1'
        );

        $med = new ParagonIE_Sodium_Core32_Int32(
            array(0x0001, 0x0000)
        );
        $this->assertSame(
            array(0x0000, 0x0002),
            $med->subInt(0xfffe)->limbs
        );

        $big = new ParagonIE_Sodium_Core32_Int32(
            array(0x7fff, 0xffff)
        );
        $this->assertSame(
            array(0x7fff, 0x0001),
            $big->subInt(0xfffe)->limbs
        );
        $this->assertSame(
            array(0x7ffe, 0xffff),
            $big->subInt(0x10000)->limbs
        );
    }

    /**
     * @covers ParagonIE_Sodium_Core32_Int32::subInt32()
     *
     * @throws SodiumException
     * @throws TypeError
     */
    public function testSubInt32()
    {
        $four = new ParagonIE_Sodium_Core32_Int32(
            array(0x0000, 0x0004)
        );

        $this->assertSame(
            array(0x0000, 0x0001),
            $four->subInt32(ParagonIE_Sodium_Core32_Int32::fromInt(3))->limbs,
            '4 - 3 = 1'
        );


        $med = new ParagonIE_Sodium_Core32_Int32(
            array(0x0001, 0x0000)
        );
        $this->assertSame(
            array(0x0000, 0x0002),
            $med->subInt32(ParagonIE_Sodium_Core32_Int32::fromInt(0xfffe))->limbs
        );

        $big = new ParagonIE_Sodium_Core32_Int32(
            array(0x7fff, 0xffff)
        );
        $this->assertSame(
            array(0x7fff, 0x0001),
            $big->subInt32(ParagonIE_Sodium_Core32_Int32::fromInt(0xfffe))->limbs
        );
        $this->assertSame(
            array(0x7ffe, 0xffff),
            $big->subInt32(ParagonIE_Sodium_Core32_Int32::fromInt(0x10000))->limbs
        );
    }

}
