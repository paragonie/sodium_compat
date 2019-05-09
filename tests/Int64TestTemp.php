<?php

/**
 * Class Int64Test
 */
class Int64TestTemp extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        if (PHP_INT_SIZE === 8) {
            $this->markTestSkipped('Only relevant to 32-bit platforms.');
        }
        ParagonIE_Sodium_Compat::$fastMult = true;
    }


    /**
     * @covers ParagonIE_Sodium_Core32_Int64::mulInt()
     * @covers ParagonIE_Sodium_Core32_Int64::mulInt64()
     * @throws SodiumException
     * @throws TypeError
     */
    public function testMult()
    {
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
    }

}
