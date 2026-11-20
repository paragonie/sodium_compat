<?php

require_once dirname(__FILE__) . '/PQPolynomialReference.php';

/**
 * @covers ParagonIE_Sodium_Core_MLDSA_Field
 * @covers ParagonIE_Sodium_Core_MLDSA_Operations
 * @covers ParagonIE_Sodium_Core_MLDSA_Ring
 * @covers ParagonIE_Sodium_Core_MLDSA_Ntt
 */
class CoreMLDSATest extends PHPUnit_Framework_TestCase
{
    public static function fieldElements()
    {
        $cases = array();
        $boundaries = array(
            0,
            1,
            2,
            4095,
            4096,
            4097,
            95231,
            95232,
            95233,
            190463,
            190464,
            190465,
            4190208,
            4190209,
            8380415,
            8380416
        );
        foreach ($boundaries as $a) {
            $cases['a=' . $a] = array($a);
        }
        return $cases;
    }

    /**
     * @dataProvider fieldElements
     */
    public function testFieldArithmeticAgainstIntegerModulus($a)
    {
        foreach (array(0, 1, 4096, 95232, 4190208, 8380416) as $b) {
            $this->assertSame(
                ($a + $b) % 8380417,
                ParagonIE_Sodium_Core_MLDSA_Field::add($a, $b),
                'add b=' . $b
            );
            $this->assertSame(
                ($a - $b + 8380417) % 8380417,
                ParagonIE_Sodium_Core_MLDSA_Field::sub($a, $b),
                'sub b=' . $b
            );
            $this->assertSame(
                PQPolynomialReference::multiplyMod($a, $b, 8380417),
                ParagonIE_Sodium_Core_MLDSA_Field::mul($a, $b),
                'mul b=' . $b
            );
        }
        $this->assertSame((8380417 - $a) % 8380417, ParagonIE_Sodium_Core_MLDSA_Field::neg($a));
        $this->assertSame(min($a, 8380417 - $a), ParagonIE_Sodium_Core_MLDSA_Field::infinityNorm($a));
        $signed = $a > 4190208 ? $a - 8380417 : $a;
        $this->assertSame($signed, ParagonIE_Sodium_Core_MLDSA_Field::symmetric($a));
        $this->assertSame($a, ParagonIE_Sodium_Core_MLDSA_Field::newFromSymmetric($signed));
    }

    public function testBarrettProductsOnDenseDeterministicInputs()
    {
        for ($i = 0; $i < 4096; ++$i) {
            $a = hexdec(substr(hash('sha256', 'left ' . $i), 0, 6)) % 8380417;
            $b = hexdec(substr(hash('sha256', 'right ' . $i), 0, 6)) % 8380417;
            $this->assertSame(
                PQPolynomialReference::multiplyMod($a, $b, 8380417),
                ParagonIE_Sodium_Core_MLDSA_Field::mul($a, $b),
                'Pair ' . $i
            );
        }
    }

    /**
     * @dataProvider fieldElements
     */
    public function testPower2Round($a)
    {
        $high = (int) floor(($a + 4095) / (8192));
        $this->assertSame(array($high, $a - $high * 8192), ParagonIE_Sodium_Core_MLDSA_Field::power2round($a));
    }

    /**
     * @dataProvider fieldElements
     * @throws SodiumException
     */
    public function testDecompositionAndHints($a)
    {
        $expected = self::decomposeReference($a);
        $this->assertSame($expected, ParagonIE_Sodium_Core_MLDSA_Field::decompose($a, 95232));
        $this->assertSame($expected[0], ParagonIE_Sodium_Core_MLDSA_Field::highBits($a, 95232));
        $this->assertSame($expected[1], ParagonIE_Sodium_Core_MLDSA_Field::lowBits($a, 95232));
        foreach (array(-95232, -1, 0, 1, 95232) as $z) {
            $changed = self::decomposeReference(($a + $z + 8380417) % 8380417);
            $hint = (int) ($expected[0] !== $changed[0]);
            $this->assertSame(
                $hint,
                ParagonIE_Sodium_Core_MLDSA_Field::makeHint($z, $a, 95232),
                'z=' . $z
            );
        }
    }

    private static function decomposeReference($a)
    {
        $low = $a % 190464;
        if ($low > 95232) {
            $low -= 190464;
        }
        if ($a - $low === 8380416) {
            return array(0, $low - 1);
        }
        return array((int) floor(($a - $low) / (190464)), $low);
    }

    /**
     * @dataProvider fieldElements
     */
    public function testFixedDivisorsAgainstIntegerDivision($a)
    {
        foreach (array(95232, 190464) as $divisor) {
            $this->assertSame(
                array((int) floor(($a) / ($divisor)), $a % $divisor),
                ParagonIE_Sodium_Core_MLDSA_Field::div($a, $divisor)
            );
        }
    }

    public function testUnsupportedDivisorIsRejected()
    {
        if (method_exists($this, 'expectException')) {
            $this->expectException('SodiumException');
        } else {
            $this->setExpectedException('SodiumException');
        }
        ParagonIE_Sodium_Core_MLDSA_Field::div(123, 7);
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
        $a = PQPolynomialReference::coefficients(8380417, $pattern);
        $ring = new ParagonIE_Sodium_Core_MLDSA_Ring();
        foreach ($a as $index => $coefficient) {
            $ring->{'c' . $index} = $coefficient;
        }
        $ntt = ParagonIE_Sodium_Core_MLDSA_Operations::ntt($ring);
        $this->assertSame($a, ParagonIE_Sodium_Core_MLDSA_Operations::inverseNtt($ntt)->toArray());
        $this->assertSame($a, $ring->toArray(), 'Input must not be mutated');
    }

    /**
     * @dataProvider polynomialPatterns
     */
    public function testNTTProductAgainstSchoolbookMultiplication($pattern)
    {
        $a = PQPolynomialReference::coefficients(8380417, $pattern);
        $b = PQPolynomialReference::coefficients(8380417, 'dense');
        $aPoly = new ParagonIE_Sodium_Core_MLDSA_Ring();
        foreach ($a as $index => $coefficient) {
            $aPoly->{'c' . $index} = $coefficient;
        }
        $bPoly = new ParagonIE_Sodium_Core_MLDSA_Ring();
        foreach ($b as $index => $coefficient) {
            $bPoly->{'c' . $index} = $coefficient;
        }
        $left = ParagonIE_Sodium_Core_MLDSA_Operations::ntt($aPoly);
        $right = ParagonIE_Sodium_Core_MLDSA_Operations::ntt($bPoly);
        $actual = ParagonIE_Sodium_Core_MLDSA_Operations::inverseNtt($left->mul($right));
        $this->assertSame(PQPolynomialReference::multiply($a, $b, 8380417), $actual->toArray());
    }

    public function testRingAndNTTArithmeticDoesNotMutateInputs()
    {
        $a = PQPolynomialReference::coefficients(8380417, 'ramp');
        $b = PQPolynomialReference::coefficients(8380417, 'dense');
        foreach (array('ParagonIE_Sodium_Core_MLDSA_Ring', 'ParagonIE_Sodium_Core_MLDSA_Ntt') as $class) {
            $left = new $class();
            foreach ($a as $index => $coefficient) {
                $left->{'c' . $index} = $coefficient;
            }
            $right = new $class();
            foreach ($b as $index => $coefficient) {
                $right->{'c' . $index} = $coefficient;
            }
            $sum = $left->add($right);
            $difference = $left->sub($right);
            for ($i = 0; $i < 256; ++$i) {
                $this->assertSame(
                    ($a[$i] + $b[$i]) % 8380417,
                    $sum[$i],
                    $class . ' sum ' . $i
                );
                $this->assertSame(
                    ($a[$i] - $b[$i] + 8380417) % 8380417,
                    $difference[$i],
                    $class . ' difference ' . $i
                );
            }
            $this->assertSame($a, $left->toArray());
            $this->assertSame($b, $right->toArray());
        }
        $ring = new ParagonIE_Sodium_Core_MLDSA_Ring();
        foreach ($b as $index => $coefficient) {
            $ring->{'c' . $index} = $coefficient;
        }
        $negated = $ring->negate();
        $scaled = $ring->scalarMul(8192);
        $signed = $ring->symmetric();
        for ($i = 0; $i < 256; ++$i) {
            $this->assertSame((8380417 - $b[$i]) % 8380417, $negated[$i]);
            $this->assertSame(PQPolynomialReference::multiplyMod($b[$i], 8192, 8380417), $scaled[$i]);
            $this->assertSame($b[$i] > 4190208 ? $b[$i] - 8380417 : $b[$i], $signed[$i]);
        }
        $this->assertSame($b, ParagonIE_Sodium_Core_MLDSA_Ring::fromSymmetric($signed)->toArray());
    }

    public static function packingWidths()
    {
        return array(
            'eta' => array(3),
            'w1' => array(6),
            't1' => array(10),
            't0' => array(13),
            'z' => array(18)
        );
    }

    /**
     * @dataProvider packingWidths
     */
    public function testUnsignedBitEncodingAgainstIndependentPacking($width)
    {
        $a = array();
        for ($i = 0; $i < 256; ++$i) {
            $a[$i] = ($i * 769 + 511) & ((1 << $width) - 1);
        }
        $expected = PQPolynomialReference::pack($a, $width);
        $poly = new ParagonIE_Sodium_Core_MLDSA_Ring();
        foreach ($a as $index => $coefficient) {
            $poly->{'c' . $index} = $coefficient;
        }
        $packed = ParagonIE_Sodium_Core_MLDSA_Operations::simpleBitPack($poly, $width);
        $this->assertSame($expected, ParagonIE_Sodium_Core_Util::intArrayToString($packed));
        $this->assertSame(
            $a,
            ParagonIE_Sodium_Core_MLDSA_Operations::simpleBitUnpack(
                array_values(unpack('C*', $expected)),
                $width
            )->toArray()
        );
    }

    public static function signedPackingWidths()
    {
        return array(
            't0' => array(12),
            'z' => array(17)
        );
    }

    /**
     * @dataProvider signedPackingWidths
     */
    public function testSignedBitEncoding($width)
    {
        $base = 1 << $width;
        $a = array();
        $encoded = array();
        for ($i = 0; $i < 256; ++$i) {
            $encoded[$i] = ($i * 769 + 511) & ((1 << ($width + 1)) - 1);
            $a[$i] = $base - $encoded[$i];
        }
        $expected = PQPolynomialReference::pack($encoded, $width + 1);
        $poly = new ParagonIE_Sodium_Core_MLDSA_Ring();
        foreach ($a as $index => $coefficient) {
            $poly->{'c' . $index} = $coefficient;
        }
        $this->assertSame($expected, ParagonIE_Sodium_Core_Util::intArrayToString(ParagonIE_Sodium_Core_MLDSA_Operations::bitPack($poly, $width)));
        $this->assertSame(
            $a,
            ParagonIE_Sodium_Core_MLDSA_Operations::bitUnpack(
                array_values(unpack('C*', $expected)),
                $width
            )->toArray()
        );
    }

    /**
     * @throws SodiumException
     */
    public function testCanonicalHintEncoding()
    {
        $hints = array();
        foreach (array(array(0, 255), array(), array(1, 128), array(17)) as $positions) {
            $hint = new ParagonIE_Sodium_Core_MLDSA_Ring();
            foreach ($positions as $position) {
                $hint[$position] = 1;
            }
            $hints[] = $hint;
        }
        $expected = array_pad(array(0, 255, 1, 128, 17), 80, 0);
        array_push($expected, 2, 2, 4, 5);
        $params = new ParagonIE_Sodium_Core_MLDSA_Params();
        $this->assertSame(
            $expected,
            ParagonIE_Sodium_Core_MLDSA_Operations::hintBitPack($params, $hints)
        );
        $decoded = ParagonIE_Sodium_Core_MLDSA_Operations::hintBitUnpack($params, $expected);
        foreach ($hints as $i => $hint) {
            $this->assertSame(
                $hint->toArray(),
                $decoded[$i]->toArray(),
                'Polynomial ' . $i
            );
        }
    }

    public static function malformedHints()
    {
        $duplicate = array_fill(0, 84, 0);
        $duplicate[0] = $duplicate[1] = 7;
        $duplicate[80] = $duplicate[81] = $duplicate[82] = $duplicate[83] = 2;
        $unordered = $duplicate;
        $unordered[0] = 8;
        $overflow = array_fill(0, 84, 0);
        $overflow[80] = 81;
        $decreasing = array_fill(0, 84, 0);
        $decreasing[80] = 1;
        $padding = array_fill(0, 84, 0);
        $padding[79] = 1;
        return array(
            'duplicate indices' => array($duplicate),
            'unsorted indices' => array($unordered),
            'endpoint exceeds omega' => array($overflow),
            'decreasing endpoints' => array($decreasing),
            'nonzero padding' => array($padding)
        );
    }

    /**
     * @dataProvider malformedHints
     */
    public function testRejectsNoncanonicalHints(array $encoded)
    {
        if (method_exists($this, 'expectException')) {
            $this->expectException('SodiumException');
        } else {
            $this->setExpectedException('SodiumException');
        }
        ParagonIE_Sodium_Core_MLDSA_Operations::hintBitUnpack(new ParagonIE_Sodium_Core_MLDSA_Params(), $encoded);
    }

    /**
     * @throws SodiumException
     */
    public function testUnrolledPolynomialRoundingAndDecomposition()
    {
        $boundaries = array();
        foreach (self::fieldElements() as $case) {
            $boundaries[] = $case[0];
        }
        $coefficients = array();
        for ($i = 0; $i < 256; ++$i) {
            $coefficients[$i] = $boundaries[$i % count($boundaries)];
        }
        $ring = new ParagonIE_Sodium_Core_MLDSA_Ring();
        foreach ($coefficients as $index => $coefficient) {
            $ring->{'c' . $index} = $coefficient;
        }
        $rounded = $ring->power2Round();
        $params = new ParagonIE_Sodium_Core_MLDSA_Params();
        $high = $ring->highBits($params);
        $low = $ring->lowBits($params);
        $norm = 0;
        foreach ($coefficients as $i => $value) {
            $roundHigh = (int) floor(($value + 4095) / (8192));
            $this->assertSame(
                $roundHigh,
                $rounded[0][$i],
                'Rounded high coefficient ' . $i
            );
            $this->assertSame(
                $value - 8192 * $roundHigh,
                $rounded[1][$i],
                'Rounded low coefficient ' . $i
            );
            $decomposed = self::decomposeReference($value);
            $this->assertSame($decomposed[0], $high[$i], 'High coefficient ' . $i);
            $this->assertSame($decomposed[1], $low[$i], 'Low coefficient ' . $i);
            $norm = max($norm, min($value, 8380417 - $value));
        }
        $this->assertSame($norm, $ring->infinityNorm());
        $this->assertSame($coefficients, $ring->toArray());
    }
}
