<?php

/**
 * Class Int64Test
 */
class Int64Test extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        if (PHP_INT_SIZE === 8) {
            $this->markTestSkipped('Only relevant to 32-bit platforms.');
        }
    }

    /**
     * @throws SodiumException
     * @throws TypeError
     */
    public function testAssociative()
    {
        // Test negative operands
        $f = new ParagonIE_Sodium_Core32_Int64(array(0, 0, 409, 49299));
        $g = new ParagonIE_Sodium_Core32_Int64(array(65535, 65535, 65369, 30902));
        $this->assertSame(
            array(65534, 62836, 38318, 53378),
            $g->mulInt64($f)->limbs,
            'G x F first run -- step one'
        );
        $this->assertSame(
            array(65534, 62836, 38318, 53378),
            $f->mulInt64($g)->limbs,
            'F x G first run -- step two'
        );
        for ($i = 64; $i >= 32; --$i) {
            $this->assertSame(
                array(65534, 62836, 38318, 53378),
                $g->mulInt64($f, $i)->limbs,
                'LOOP: G x F -- Failed at $i = ' . $i
            );
        }
        for ($i = 64; $i >= 32; --$i) {
            $this->assertSame(
                array(65534, 62836, 38318, 53378),
                $f->mulInt64($g, $i)->limbs,
                'LOOP: F x G -- Failed at $i = ' . $i
            );
        }
    }

    /**
     * @throws SodiumException
     * @throws TypeError
     */
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
     * @throws SodiumException
     * @throws TypeError
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
        $tests = array(
            array('1660a70000000000', '0000c002ec140000', 21)
        );
        foreach ($tests as $sample => $test) {
            list ($A, $B, $C) = $test;
            $a = ParagonIE_Sodium_Core32_Int64::fromReverseString(ParagonIE_Sodium_Core_Util::hex2bin($A));
            $b = ParagonIE_Sodium_Core32_Int64::fromReverseString(ParagonIE_Sodium_Core_Util::hex2bin($B));
            $this->assertEquals(
                $b->limbs,
                $a->shiftLeft($C)->limbs,
                'Sample ' .$sample
            );
        }
    }

    /**
     * @covers ParagonIE_Sodium_Core32_Int64::addInt64()
     * @throws SodiumException
     * @throws TypeError
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
     * @covers ParagonIE_Sodium_Core32_Int64::mulInt()
     * @covers ParagonIE_Sodium_Core32_Int64::mulInt64()
     * @throws SodiumException
     * @throws TypeError
     */
    public function testMult()
    {
        $begin = new ParagonIE_Sodium_Core32_Int64(
            array(0x1234, 0x5678, 0x9abc, 0xdef0)
        );

        $this->assertSame(
            array(0x2468, 0xacf1, 0x3579, 0xbde0),
            $begin->mulInt(2)->limbs
        );
        $this->assertSame(
            array(0x48d1, 0x59e2, 0x6af3, 0x7bc0),
            $begin->mulInt(4)->limbs
        );
        $this->assertSame(
            array(0x5b05, 0xb05b, 0x05b0, 0x5ab0),
            $begin->mulInt(5)->limbs
        );
        $this->assertSame(
            array(0, 0, 0, 0),
            $begin->mulInt(0)->limbs
        );

        $this->assertSame(
            array(0x48d1, 0x59e2, 0x6af3, 0x7bc0),
            $begin->mulInt64(new ParagonIE_Sodium_Core32_Int64(array(0, 0, 0, 4)))->limbs
        );

        $negOne = new ParagonIE_Sodium_Core32_Int64(array(0xffff, 0xffff, 0xffff, -1 & 0xffff));
        $this->assertSame(
            array(0xffff, 0xffff, 0xffff, 0xfffb),
            $negOne->mulInt(5)->limbs
        );
        $this->assertSame(
            array(0, 0, 0, 5),
            $negOne->mulInt(-5)->limbs
        );

        $one = new ParagonIE_Sodium_Core32_Int64(array(0, 0, 0, 1));
        $this->assertSame(
            array(0, 0, 0, 5),
            $one->mulInt(5)->limbs
        );
        $two = new ParagonIE_Sodium_Core32_Int64(array(0, 0, 0, 2));
        $this->assertSame(
            array(0, 0, 0, 10),
            $two->mulInt(5)->limbs
        );

        for ($j = 0; $j < 64; ++$j) {
            $baseSmall = random_int(1, 65536);
            $base = new ParagonIE_Sodium_Core32_Int64(array(0, 0, 0, $baseSmall));
            for ($i = 0; $i < 64; ++$i) {
                $value = random_int(1, 65536);
                $result = ($baseSmall * $value);
                $expected = array(
                    0,
                    0,
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

        $negTwo = new ParagonIE_Sodium_Core32_Int64(array(0xffff, 0xffff, 0xffff, -2 & 0xffff));
        $this->assertSame(
            array(0, 0, 0, 0),
            $negTwo->mulInt64(new ParagonIE_Sodium_Core32_Int64())->limbs
        );
        $this->assertSame(
            array(0, 0, 0, 2),
            $negTwo->mulInt64($negOne)->limbs
        );
        $this->assertSame(
            $negTwo->limbs,
            $negTwo->mulInt64($one)->limbs
        );
        $three = new ParagonIE_Sodium_Core32_Int64(array(0, 0, 0, 3));
        $this->assertSame(
            array(0xffff, 0xffff, 0xffff, -6 & 0xffff),
            $negTwo->mulInt64($three)->limbs
        );
        $negThree = new ParagonIE_Sodium_Core32_Int64(array(0xffff, 0xffff, 0xffff, -3 & 0xffff));
        $this->assertSame(
            array(0, 0, 0, 6),
            $negTwo->mulInt64($negThree)->limbs
        );

        $f1 = ParagonIE_Sodium_Core32_Int64::fromReverseString(ParagonIE_Sodium_Core_Util::hex2bin('0000000000000000'));
        $g0 = ParagonIE_Sodium_Core32_Int64::fromReverseString(ParagonIE_Sodium_Core_Util::hex2bin('6a5882feffffffff'));
        $this->assertSame(
            array(0, 0, 0, 0),
            $g0->mulInt64($f1)->limbs
        );
        $this->assertSame(
            array(0, 0, 0, 0),
            $f1->mulInt64($g0)->limbs
        );
    }

    /**
     * @covers ParagonIE_Sodium_Core32_Int64::mulInt()
     * @covers ParagonIE_Sodium_Core32_Int64::mulInt64()
     * @throws TypeError
     */
    public function testMultNegative()
    {
        $a = new ParagonIE_Sodium_Core32_Int64(
            array(0, 0, 0, 3)
        );
        $na = new ParagonIE_Sodium_Core32_Int64(
            array(0xffff, 0xffff, 0xffff, 0xfffd) // -3
        );
        $b = new ParagonIE_Sodium_Core32_Int64(
            array(0, 0, 0, 14)
        );
        $nb = new ParagonIE_Sodium_Core32_Int64(
            array(0xffff, 0xffff, 0xffff, 0xfff2) // -14
        );

        $this->assertEquals(
            $a->mulInt64($b)->limbs,
            $na->mulInt64($nb)->limbs
        );

        $this->assertEquals(
            $a->mulInt64($nb)->limbs,
            $na->mulInt64($b)->limbs
        );

        $this->assertEquals(
            42,
            $a->mulInt64($b)->toInt32()->toInt()
        );
        $this->assertEquals(
            42,
            $na->mulInt64($nb)->toInt32()->toInt()
        );
        $this->assertEquals(
            -42,
            $na->mulInt64($b)->toInt32()->toInt()
        );
        $this->assertEquals(
            -42,
            $a->mulInt64($nb)->toInt32()->toInt()
        );
    }

    /**
     * @covers ParagonIE_Sodium_Core32_Int64::rotateLeft()
     * @throws TypeError
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
     * @throws TypeError
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

    /**
     * @throws SodiumException
     * @throws TypeError
     */
    public function testShift()
    {
        $int64 = new ParagonIE_Sodium_Core32_Int64(
            array(0x0123, 0x4567, 0x89ab, 0xcdef)
        );

        $this->assertSame(
            array(0x0246, 0x8acf, 0x1357, 0x9bde),
            $int64->shiftLeft(1)->limbs
        );

        $this->assertSame(
            array(0x0000, 0x0123, 0x4567, 0x89ab),
            $int64->shiftRight(16)->limbs
        );

        $second = new ParagonIE_Sodium_Core32_Int64(
            array(0x0001, 0x0000, 0x0000, 0x0000)
        );
        $this->assertSame(
            array(0x1000, 0x0000, 0x0000, 0x0000),
            $second->shiftLeft(12)->limbs
        );
        $this->assertSame(
            array(0x0000, 0x0000, 0x0001, 0x0000),
            $second->shiftRight(32)->limbs
        );

        $real = new ParagonIE_Sodium_Core32_Int64(
            array(0, 3, 26984, 29696)
        );
        $this->assertSame(
            array(0, 0, 0, 218),
            $real->shiftRight(26)->limbs
        );

        $neg = new ParagonIE_Sodium_Core32_Int64(
            array(0xfedc, 0xba98, 0x7654, 0x3210)
        );
        $this->assertSame(
            array(0xfffe, 0xdcba, 0x9876, 0x5432),
            $neg->shiftRight(8)->limbs
        );
        $this->assertSame(
            array(0xffff, 0xfedc, 0xba98, 0x7654),
            $neg->shiftRight(16)->limbs
        );
        $this->assertSame(
            array(0xffff, 0xfffe, 0xdcba, 0x9876),
            $neg->shiftRight(24)->limbs
        );
        $this->assertSame(
            array(0xffff, 0xffff, 0xfedc, 0xba98),
            $neg->shiftRight(32)->limbs
        );
        $neg = new ParagonIE_Sodium_Core32_Int64(
            array(0xffff, 0xfedc, 0xba98, 0x7654)
        );
        $this->assertSame(
            array(0xffff, 0xfffe, 0xdcba, 0x9876),
            $neg->shiftRight(8)->limbs
        );
    }

    public function testSubInt64()
    {
        $tests = array(
            array('07daac0d00000000', 'b1a1a51f00000000', 'aac7f81100000000'),
            array('98be457800000000', '70f3e84900000000', 'd834a3d1ffffffff'),
            array('c368b597ab6ee13c', 'ffd325e6adf3d40f', '3c6b704e0285f3d2'),
            array('c85d2b21ba98ff00', '938a6e5a72b9c400', 'cb2c4339b820c5ff'),
            array('0000c002ec140000', '3669be02ec140000', '3669feffffffffff'),
            array('0000c002e0140000', '3669be02ec140000', '3669feff0b000000')
        );
        foreach ($tests as $sample => $test) {
            list ($A, $B, $C) = $test;
            $a = ParagonIE_Sodium_Core32_Int64::fromReverseString(ParagonIE_Sodium_Core_Util::hex2bin($A));
            $b = ParagonIE_Sodium_Core32_Int64::fromReverseString(ParagonIE_Sodium_Core_Util::hex2bin($B));
            $c = ParagonIE_Sodium_Core32_Int64::fromReverseString(ParagonIE_Sodium_Core_Util::hex2bin($C));
            $this->assertEquals(
                $c->limbs,
                $b->subInt64($a)->limbs,
                'Sample ' .$sample
            );
        }
    }

    /**
     * @throws SodiumException
     * @throws TypeError
     */
    public function testConvert()
    {
        $int64 = new ParagonIE_Sodium_Core32_Int32(array(0xffff, 0xffff), true);
        $added = $int64->addInt(2)->toInt64();

        $this->assertSame(array(0, 1, 0, 1), $added->limbs);

        $reverse = $added->toInt32();
        $this->assertSame(array(0, 1), $reverse->limbs);
        $this->assertSame(1, $reverse->overflow);
    }
}
