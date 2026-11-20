<?php

require_once dirname(__FILE__) . '/PQPolynomialReference.php';

/**
 * @covers ParagonIE_Sodium_Core_MLKem_FieldElement
 * @covers ParagonIE_Sodium_Core_MLKem_Operations
 * @covers ParagonIE_Sodium_Core_MLKem_RingElement
 * @covers ParagonIE_Sodium_Core_MLKem_NttElement
 */
class CoreMLKemTest extends PHPUnit_Framework_TestCase
{
    public static function fieldPairs()
    {
        $cases = array();
        foreach (array(0, 1, 2, 1664, 1665, 3327, 3328) as $a) {
            foreach (array(0, 1, 2, 1664, 1665, 3327, 3328) as $b) {
                $cases[$a . ',' . $b] = array($a, $b);
            }
        }
        return $cases;
    }

    /**
     * @dataProvider fieldPairs
     */
    public function testFieldArithmetic($a, $b)
    {
        $this->assertSame(($a + $b) % 3329, ParagonIE_Sodium_Core_MLKem_FieldElement::add($a, $b));
        $this->assertSame(($a - $b + 3329) % 3329, ParagonIE_Sodium_Core_MLKem_FieldElement::sub($a, $b));
        $this->assertSame(($a * $b) % 3329, ParagonIE_Sodium_Core_MLKem_FieldElement::mul($a, $b));
        $this->assertSame(($a * ($b + 1)) % 3329, ParagonIE_Sodium_Core_MLKem_FieldElement::mulSub($a, $b, 3328));
        $this->assertSame(
            ($a * $b + 3328 * $a) % 3329,
            ParagonIE_Sodium_Core_MLKem_FieldElement::addMul($a, $b, 3328, $a)
        );
    }

    public function testBarrettReductionBounds()
    {
        foreach (array(0, 1, 3328, 3329, 3330, 6657, 3328 * 3328, 2 * 3329 * 3328) as $a) {
            $this->assertSame($a % 3329, ParagonIE_Sodium_Core_MLKem_FieldElement::reduce($a), 'Input ' . $a);
        }
        for ($a = 0; $a < 6658; ++$a) {
            $this->assertSame($a % 3329, ParagonIE_Sodium_Core_MLKem_FieldElement::reduceOnce($a), 'Input ' . $a);
        }
    }

    public static function widths()
    {
        return array(
            'message bits' => array(1),
            'v bits' => array(4),
            'u bits' => array(10)
        );
    }

    /**
     * @dataProvider widths
     */
    public function testCompressionForEveryFieldElement($width)
    {
        for ($a = 0; $a < 3329; ++$a) {
            $expected = (int) floor((($a << $width) + 1664) / (3329)) & ((1 << $width) - 1);
            $this->assertSame(
                $expected,
                ParagonIE_Sodium_Core_MLKem_FieldElement::compress($a, $width),
                'Coefficient ' . $a
            );
        }
    }

    /**
     * @dataProvider widths
     */
    public function testDecompressionForEveryEncoding($width)
    {
        for ($a = 0; $a < (1 << $width); ++$a) {
            $expected = (int) floor((3329 * $a + (1 << ($width - 1))) / (1 << $width));
            $this->assertSame(
                $expected,
                ParagonIE_Sodium_Core_MLKem_FieldElement::decompress($a, $width),
                'Encoding ' . $a
            );
        }
    }

    public static function polynomialPatterns()
    {
        return array(
            'zero' => array('zero'),
            'one' => array('one'),
            'wrap' => array('wrap'),
            'ramp' => array('ramp'),
            'dense' => array('dense')
        );
    }

    /**
     * @dataProvider polynomialPatterns
     */
    public function testNTTInverse($pattern)
    {
        $coefficients = PQPolynomialReference::coefficients(3329, $pattern);
        $ring = ParagonIE_Sodium_Core_MLKem_RingElement::fromArray($coefficients);
        $ntt = ParagonIE_Sodium_Core_MLKem_Operations::ntt($ring);
        $this->assertSame($coefficients, ParagonIE_Sodium_Core_MLKem_Operations::inverseNTT($ntt)->toArray());
        $this->assertSame($coefficients, $ring->toArray(), 'Input must not be mutated');
    }

    /**
     * @dataProvider polynomialPatterns
     */
    public function testNTTProductAgainstSchoolbookMultiplication($pattern)
    {
        $a = PQPolynomialReference::coefficients(3329, $pattern);
        $b = PQPolynomialReference::coefficients(3329, 'dense');
        $product = ParagonIE_Sodium_Core_MLKem_Operations::nttMul(
            ParagonIE_Sodium_Core_MLKem_Operations::ntt(ParagonIE_Sodium_Core_MLKem_RingElement::fromArray($a)),
            ParagonIE_Sodium_Core_MLKem_Operations::ntt(ParagonIE_Sodium_Core_MLKem_RingElement::fromArray($b))
        );
        $this->assertSame(
            PQPolynomialReference::multiply($a, $b, 3329),
            ParagonIE_Sodium_Core_MLKem_Operations::inverseNTT($product)->toArray()
        );
    }

    public function testPolynomialAdditionAndSubtraction()
    {
        $a = PQPolynomialReference::coefficients(3329, 'ramp');
        $b = PQPolynomialReference::coefficients(3329, 'dense');
        $left = ParagonIE_Sodium_Core_MLKem_RingElement::fromArray($a);
        $right = ParagonIE_Sodium_Core_MLKem_RingElement::fromArray($b);
        $sum = ParagonIE_Sodium_Core_MLKem_Operations::polyAdd($left, $right);
        $difference = ParagonIE_Sodium_Core_MLKem_Operations::polySub($left, $right);
        for ($i = 0; $i < 256; ++$i) {
            $this->assertSame(($a[$i] + $b[$i]) % 3329, $sum[$i], 'Sum coefficient ' . $i);
            $this->assertSame(($a[$i] - $b[$i] + 3329) % 3329, $difference[$i], 'Difference coefficient ' . $i);
        }
        $this->assertSame($a, $left->toArray());
        $this->assertSame($b, $right->toArray());
    }

    public function testTwelveBitSerializationAgainstIndependentPacking()
    {
        $coefficients = PQPolynomialReference::coefficients(3329, 'dense');
        $expected = PQPolynomialReference::pack($coefficients, 12);
        $poly = ParagonIE_Sodium_Core_MLKem_NttElement::fromArray($coefficients);
        $this->assertSame($expected, ParagonIE_Sodium_Core_MLKem_Operations::polyByteEncode($poly));
        $this->assertSame($coefficients, ParagonIE_Sodium_Core_MLKem_Operations::polyByteDecode($expected)->toArray());
    }

    public static function noncanonicalCoefficients()
    {
        return array(
            'first' => array(0),
            'second' => array(1),
            'penultimate' => array(254),
            'last' => array(255)
        );
    }

    /**
     * @dataProvider noncanonicalCoefficients
     */
    public function testRejectsNoncanonicalCoefficient($index)
    {
        $coefficients = array_fill(0, 256, 0);
        $coefficients[$index] = 3329;
        if (method_exists($this, 'expectException')) {
            $this->expectException('SodiumException');
        } else {
            $this->setExpectedException('SodiumException');
        }
        ParagonIE_Sodium_Core_MLKem_Operations::polyByteDecode(PQPolynomialReference::pack($coefficients, 12));
    }

    public static function badPolynomialLengths()
    {
        return array(
            'empty' => array(0),
            'truncated' => array(383),
            'oversized' => array(385)
        );
    }

    /**
     * @dataProvider badPolynomialLengths
     */
    public function testRejectsIncorrectPolynomialLength($length)
    {
        if (method_exists($this, 'expectException')) {
            $this->expectException('SodiumException');
        } else {
            $this->setExpectedException('SodiumException');
        }
        ParagonIE_Sodium_Core_MLKem_Operations::polyByteDecode(str_repeat("\0", $length));
    }

    /**
     * @dataProvider widths
     */
    public function testCompressedEncodingAgainstIndependentPacking($width)
    {
        $compressed = array();
        $coefficients = array();
        for ($i = 0; $i < 256; ++$i) {
            $compressed[$i] = ($i * 769 + 511) & ((1 << $width) - 1);
            $coefficients[$i] = (int) floor((3329 * $compressed[$i] + (1 << ($width - 1))) / (1 << $width));
        }
        $expected = PQPolynomialReference::pack($compressed, $width);
        $poly = ParagonIE_Sodium_Core_MLKem_RingElement::fromArray($coefficients);
        $this->assertSame($expected, ParagonIE_Sodium_Core_MLKem_Operations::ringCompressAndEncode($poly, $width));
        $this->assertSame(
            $coefficients,
            ParagonIE_Sodium_Core_MLKem_Operations::ringDecodeAndDecompress($expected, $width)->toArray()
        );
    }
}
