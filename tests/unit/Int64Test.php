<?php

class Int64Test extends PHPUnit_Framework_TestCase
{
    public function testConversion()
    {
        $binary = ParagonIE_Sodium_Compat::hex2bin("0123456789abcdef");
        $from = ParagonIE_Sodium_Core32_Int64::fromString($binary);
        $this->assertSame(
            array(0x0123, 0x4567, 0x89ab, 0xcdef),
            $from->limbs,
            'fromString()'
        );
        $this->assertSame(
            bin2hex($binary),
            bin2hex((string) $from)
        );

    }

    /**
     * @covers ParagonIE_Sodium_Core32_Int64::addInt64()
     */
    public function testAddInt64()
    {
        $one = new ParagonIE_Sodium_Core32_Int64(
            array(0x0000, 0x0000, 0x0000, 0x0001)
        );

        $this->assertSame(
            array(0x0000, 0x0000, 0x0000, 0x0004),
            $one->addInt64(
                new ParagonIE_Sodium_Core32_Int64(
                    array(0x0000, 0x0000, 0x0000, 0x0003)
                )
            )->limbs,
            'Adding 1 to 3 should yield 4'
        );

        $this->assertSame(
            array(0x0000, 0x0001, 0x0000, 0x0000),
            $one->addInt64(
                new ParagonIE_Sodium_Core32_Int64(
                    array(0x0000, 0x0000, 0xffff, 0xffff)
                )
            )->limbs,
            'Adding 1 to 0xfffffffff should yield 0x1000000000'
        );
        $this->assertSame(
            array(0x0000, 0x0000, 0x0000, 0x0000),
            $one->addInt64(
                new ParagonIE_Sodium_Core32_Int64(
                    array(0xffff, 0xffff, 0xffff, 0xffff)
                )
            )->limbs,
            'Adding 1 to 0xfffffffffffffffff should yield 0, when conforming to uint64'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Core32_Int64::addInt64()
     */
    public function testAddInt()
    {
        $one = new ParagonIE_Sodium_Core32_Int64(
            array(0x0000, 0x0000, 0x0000, 0x0001)
        );

        $this->assertSame(
            array(0x0000, 0x0000, 0x0000, 0x0004),
            $one->addInt(3)->limbs,
            'Adding 1 to 3 should yield 4'
        );

        $big = new ParagonIE_Sodium_Core32_Int64(
            array(0x0000, 0x0000, 0xffff, 0xffff)
        );
        $this->assertSame(
            array(0x0000, 0x0001, 0x0000, 0x0002),
            $big->addInt(3)->limbs
        );

        $vbig = new ParagonIE_Sodium_Core32_Int64(
            array(0xffff, 0xffff, 0xffff, 0xffff)
        );
        $this->assertSame(
            array(0x0000, 0x0000, 0x0000, 0x0000),
            $vbig->addInt(1)->limbs
        );
        $this->assertSame(
            array(0x0000, 0x0000, 0x0000, 0x0001),
            $vbig->addInt(2)->limbs
        );
    }

    /**
     * @covers ParagonIE_Sodium_Core32_Int64::rotateLeft()
     */
    public function testRotateLeft()
    {
        $int64 = new ParagonIE_Sodium_Core32_Int64(
            array(0x0123, 0x4567, 0x89ab, 0xcdef)
        );

        $this->assertSame(
            $int64->limbs,
            $int64->rotateLeft(0)->limbs,
            'NOP'
        );

        $this->assertSame(
            array(0x4567, 0x89ab, 0xcdef, 0x0123),
            $int64->rotateLeft(16)->limbs,
            'Rotate left by 16'
        );

        $this->assertSame(
            array(0x89ab, 0xcdef, 0x0123, 0x4567),
            $int64->rotateLeft(32)->limbs,
            'Rotate left by 32'
        );

        $this->assertSame(
            array(0x1234, 0x5678, 0x9abc, 0xdef0),
            $int64->rotateLeft(4)->limbs,
            'Rotate left by 4'
        );

        $this->assertSame(
            array(0x0246, 0x8acf, 0x1357, 0x9bde),
            $int64->rotateLeft(1)->limbs,
            'Rotate left by 1'
        );

        $second = new ParagonIE_Sodium_Core32_Int64(
            array(0x0001, 0x0000, 0x0000, 0x0000)
        );

        $this->assertSame(
            array(0x0000, 0x0000, 0x0000, 0x0001),
            $second->rotateLeft(16)->limbs,
            'Rotate left by 16'
        );
        $this->assertSame(
            array(0x0000, 0x0000, 0x0000, 0x8000),
            $second->rotateLeft(31)->limbs,
            'Rotate left by 31'
        );
        $this->assertSame(
            array(0x0000, 0x0000, 0x0001, 0x0000),
            $second->rotateLeft(32)->limbs,
            'Rotate left by 32'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Core32_Int64::rotateRight()
     */
    public function testRotateRight()
    {
        $int64 = new ParagonIE_Sodium_Core32_Int64(
            array(0x0123, 0x4567, 0x89ab, 0xcdef)
        );

        $this->assertSame(
            $int64->limbs,
            $int64->rotateRight(0)->limbs,
            'NOP'
        );

        $this->assertSame(
            array(0xcdef, 0x0123, 0x4567, 0x89ab),
            $int64->rotateRight(16)->limbs,
            'Rotate right by 16'
        );

        $this->assertSame(
            array(0x89ab, 0xcdef, 0x0123, 0x4567),
            $int64->rotateRight(32)->limbs,
            'Rotate right by 32'
        );

        $this->assertSame(
            array(0xf012, 0x3456, 0x789a, 0xbcde),
            $int64->rotateRight(4)->limbs,
            'Rotate right by 4'
        );

        $this->assertSame(
            array(0x8091, 0xa2b3, 0xc4d5, 0xe6f7),
            $int64->rotateRight(1)->limbs,
            'Rotate right by 1'
        );

        $second = new ParagonIE_Sodium_Core32_Int64(
            array(0x0001, 0x0000, 0x0000, 0x0000)
        );

        $this->assertSame(
            array(0x0000, 0x0001, 0x0000, 0x0000),
            $second->rotateRight(16)->limbs,
            'Rotate right by 16'
        );
        $this->assertSame(
            array(0x0000, 0x0000, 0x0002, 0x0000),
            $second->rotateRight(31)->limbs,
            'Rotate right by 31'
        );
        $this->assertSame(
            array(0x0000, 0x8000, 0x0000, 0x0000),
            $second->rotateRight(1)->limbs,
            'Rotate right by 1'
        );
        $this->assertSame(
            array(0x0000, 0x0000, 0x0001, 0x0000),
            $second->rotateRight(32)->limbs,
            'Rotate right by 32'
        );
    }
}
