<?php

/**
 * @covers ParagonIE_Sodium_Core_Object256
 */
class CoreObject256Test extends PHPUnit_Framework_TestCase
{
    public static function containers()
    {
        return array(
            'ML-KEM ring' => array('ParagonIE_Sodium_Core_MLKem_RingElement'),
            'ML-KEM NTT' => array('ParagonIE_Sodium_Core_MLKem_NttElement'),
            'ML-DSA ring' => array('ParagonIE_Sodium_Core_MLDSA_Ring'),
            'ML-DSA NTT' => array('ParagonIE_Sodium_Core_MLDSA_Ntt')
        );
    }

    /**
     * @dataProvider containers
     */
    public function testCoefficientOrderAndCloneIsolation($class)
    {
        $coefficients = range(0, 255);
        $poly = new $class();
        foreach ($coefficients as $index => $coefficient) {
            $poly->{'c' . $index} = $coefficient;
        }
        $this->assertSame($coefficients, $poly->toArray());
        for ($i = 0; $i < 256; ++$i) {
            $this->assertSame($i, $poly[$i], 'Index ' . $i);
            $this->assertSame($i, $poly->{'c' . $i}, 'Property ' . $i);
        }
        $clone = clone $poly;
        $clone[255] = 1234;
        unset($clone[1]);
        $this->assertSame(255, $poly[255]);
        $this->assertSame(1, $poly[1]);
        $this->assertSame(1234, $clone[255]);
        $this->assertSame(0, $clone[1]);
        $this->assertCount(256, $clone->toArray());
    }

    /**
     * @dataProvider containers
     */
    public function testZeroAndOffsetBounds($class)
    {
        $poly = call_user_func(array($class, 'zero'));
        $this->assertSame(array_fill(0, 256, 0), $poly->toArray());
        $this->assertFalse(isset($poly[-1]));
        $this->assertTrue(isset($poly[0]));
        $this->assertTrue(isset($poly[255]));
        $this->assertFalse(isset($poly[256]));
    }

    /**
     * @dataProvider containers
     */
    public function testAppendingToFixedSizePolynomialIsRejected($class)
    {
        $poly = new $class();
        if (method_exists($this, 'expectException')) {
            $this->expectException('SodiumException');
        } else {
            $this->setExpectedException('SodiumException');
        }
        $poly[] = 1;
    }
}
