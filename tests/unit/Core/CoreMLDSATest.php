<?php

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(ParagonIE_Sodium_Core_MLDSA_Field::class)]
#[CoversClass(ParagonIE_Sodium_Core_MLDSA_Operations::class)]
#[CoversClass(ParagonIE_Sodium_Core_MLDSA_Ring::class)]
#[CoversClass(ParagonIE_Sodium_Core_MLDSA_Ntt::class)]
class CoreMLDSATest extends TestCase
{
    public static function fieldElements(): array
    {
        $cases = [];
        $boundaries = [
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
        ];
        foreach ($boundaries as $a) {
            $cases['a=' . $a] = [$a];
        }
        return $cases;
    }

    /**
     * @dataProvider fieldElements
     */
    #[DataProvider('fieldElements')]
    public function testFieldArithmeticAgainstIntegerModulus(int $a): void
    {
        foreach ([0, 1, 4096, 95232, 4190208, 8380416] as $b) {
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
                ($a * $b) % 8380417,
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

    public function testBarrettProductsOnDenseDeterministicInputs(): void
    {
        for ($i = 0; $i < 4096; ++$i) {
            $a = hexdec(substr(hash('sha256', 'left ' . $i), 0, 6)) % 8380417;
            $b = hexdec(substr(hash('sha256', 'right ' . $i), 0, 6)) % 8380417;
            $this->assertSame(
                ($a * $b) % 8380417,
                ParagonIE_Sodium_Core_MLDSA_Field::mul($a, $b),
                'Pair ' . $i
            );
        }
    }

    /**
     * @dataProvider fieldElements
     */
    #[DataProvider('fieldElements')]
    public function testPower2Round(int $a): void
    {
        $high = intdiv($a + 4095, 8192);
        $this->assertSame([$high, $a - $high * 8192], ParagonIE_Sodium_Core_MLDSA_Field::power2round($a));
    }

    /**
     * @dataProvider fieldElements
     * @throws SodiumException
     */
    #[DataProvider('fieldElements')]
    public function testDecompositionAndHints(int $a): void
    {
        $expected = self::decomposeReference($a);
        $this->assertSame($expected, ParagonIE_Sodium_Core_MLDSA_Field::decompose($a, 95232));
        $this->assertSame($expected[0], ParagonIE_Sodium_Core_MLDSA_Field::highBits($a, 95232));
        $this->assertSame($expected[1], ParagonIE_Sodium_Core_MLDSA_Field::lowBits($a, 95232));
        foreach ([-95232, -1, 0, 1, 95232] as $z) {
            $changed = self::decomposeReference(($a + $z + 8380417) % 8380417);
            $hint = (int) ($expected[0] !== $changed[0]);
            $this->assertSame(
                $hint,
                ParagonIE_Sodium_Core_MLDSA_Field::makeHint($z, $a, 95232),
                'z=' . $z
            );
        }
    }

    private static function decomposeReference(int $a): array
    {
        $low = $a % 190464;
        if ($low > 95232) {
            $low -= 190464;
        }
        if ($a - $low === 8380416) {
            return [0, $low - 1];
        }
        return [intdiv($a - $low, 190464), $low];
    }

    /**
     * @dataProvider fieldElements
     */
    #[DataProvider('fieldElements')]
    public function testFixedDivisorsAgainstIntegerDivision(int $a): void
    {
        foreach ([95232, 190464] as $divisor) {
            $this->assertSame(
                [intdiv($a, $divisor), $a % $divisor],
                ParagonIE_Sodium_Core_MLDSA_Field::div($a, $divisor)
            );
        }
    }

    public function testUnsupportedDivisorIsRejected(): void
    {
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Core_MLDSA_Field::div(123, 7);
    }

    public static function polynomialPatterns(): array
    {
        return [
            'zero' => ['zero'],
            'one' => ['one'],
            'wrap' => ['wrap'],
            'ramp' => ['ramp'],
            'dense' => ['dense']
        ];
    }

    /**
     * @dataProvider polynomialPatterns
     */
    #[DataProvider('polynomialPatterns')]
    public function testNTTInverse(string $pattern): void
    {
        $a = PQPolynomialReference::coefficients(8380417, $pattern);
        $ring = new ParagonIE_Sodium_Core_MLDSA_Ring(...$a);
        $ntt = ParagonIE_Sodium_Core_MLDSA_Operations::ntt($ring);
        $this->assertSame($a, ParagonIE_Sodium_Core_MLDSA_Operations::inverseNtt($ntt)->toArray());
        $this->assertSame($a, $ring->toArray(), 'Input must not be mutated');
    }

    /**
     * @dataProvider polynomialPatterns
     */
    #[DataProvider('polynomialPatterns')]
    public function testNTTProductAgainstSchoolbookMultiplication(string $pattern): void
    {
        $a = PQPolynomialReference::coefficients(8380417, $pattern);
        $b = PQPolynomialReference::coefficients(8380417, 'dense');
        $left = ParagonIE_Sodium_Core_MLDSA_Operations::ntt(new ParagonIE_Sodium_Core_MLDSA_Ring(...$a));
        $right = ParagonIE_Sodium_Core_MLDSA_Operations::ntt(new ParagonIE_Sodium_Core_MLDSA_Ring(...$b));
        $actual = ParagonIE_Sodium_Core_MLDSA_Operations::inverseNtt($left->mul($right));
        $this->assertSame(PQPolynomialReference::multiply($a, $b, 8380417), $actual->toArray());
    }

    public function testRingAndNTTArithmeticDoesNotMutateInputs(): void
    {
        $a = PQPolynomialReference::coefficients(8380417, 'ramp');
        $b = PQPolynomialReference::coefficients(8380417, 'dense');
        foreach ([ParagonIE_Sodium_Core_MLDSA_Ring::class, ParagonIE_Sodium_Core_MLDSA_Ntt::class] as $class) {
            $left = new $class(...$a);
            $right = new $class(...$b);
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
        $ring = new ParagonIE_Sodium_Core_MLDSA_Ring(...$b);
        $negated = $ring->negate();
        $scaled = $ring->scalarMul(8192);
        $signed = $ring->symmetric();
        for ($i = 0; $i < 256; ++$i) {
            $this->assertSame((8380417 - $b[$i]) % 8380417, $negated[$i]);
            $this->assertSame(($b[$i] * 8192) % 8380417, $scaled[$i]);
            $this->assertSame($b[$i] > 4190208 ? $b[$i] - 8380417 : $b[$i], $signed[$i]);
        }
        $this->assertSame($b, ParagonIE_Sodium_Core_MLDSA_Ring::fromSymmetric($signed)->toArray());
    }

    public static function packingWidths(): array
    {
        return [
            'eta' => [3],
            'w1' => [6],
            't1' => [10],
            't0' => [13],
            'z' => [18]
        ];
    }

    /**
     * @dataProvider packingWidths
     */
    #[DataProvider('packingWidths')]
    public function testUnsignedBitEncodingAgainstIndependentPacking(int $width): void
    {
        $a = [];
        for ($i = 0; $i < 256; ++$i) {
            $a[$i] = ($i * 769 + 511) & ((1 << $width) - 1);
        }
        $expected = PQPolynomialReference::pack($a, $width);
        $poly = new ParagonIE_Sodium_Core_MLDSA_Ring(...$a);
        $packed = ParagonIE_Sodium_Core_MLDSA_Operations::simpleBitPack($poly, $width);
        $this->assertSame($expected, pack('C*', ...$packed));
        $this->assertSame(
            $a,
            ParagonIE_Sodium_Core_MLDSA_Operations::simpleBitUnpack(
                array_values(unpack('C*', $expected)),
                $width
            )->toArray()
        );
    }

    public static function signedPackingWidths(): array
    {
        return [
            't0' => [12],
            'z' => [17]
        ];
    }

    /**
     * @dataProvider signedPackingWidths
     */
    #[DataProvider('signedPackingWidths')]
    public function testSignedBitEncoding(int $width): void
    {
        $base = 1 << $width;
        $a = [];
        $encoded = [];
        for ($i = 0; $i < 256; ++$i) {
            $encoded[$i] = ($i * 769 + 511) & ((1 << ($width + 1)) - 1);
            $a[$i] = $base - $encoded[$i];
        }
        $expected = PQPolynomialReference::pack($encoded, $width + 1);
        $poly = new ParagonIE_Sodium_Core_MLDSA_Ring(...$a);
        $this->assertSame($expected, pack('C*', ...ParagonIE_Sodium_Core_MLDSA_Operations::bitPack($poly, $width)));
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
    public function testCanonicalHintEncoding(): void
    {
        $hints = [];
        foreach ([[0, 255], [], [1, 128], [17]] as $positions) {
            $hint = new ParagonIE_Sodium_Core_MLDSA_Ring();
            foreach ($positions as $position) {
                $hint[$position] = 1;
            }
            $hints[] = $hint;
        }
        $expected = array_pad([0, 255, 1, 128, 17], 80, 0);
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

    public static function malformedHints(): array
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
        return [
            'duplicate indices' => [$duplicate],
            'unsorted indices' => [$unordered],
            'endpoint exceeds omega' => [$overflow],
            'decreasing endpoints' => [$decreasing],
            'nonzero padding' => [$padding]
        ];
    }

    /**
     * @dataProvider malformedHints
     */
    #[DataProvider('malformedHints')]
    public function testRejectsNoncanonicalHints(array $encoded): void
    {
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Core_MLDSA_Operations::hintBitUnpack(new ParagonIE_Sodium_Core_MLDSA_Params(), $encoded);
    }

    /**
     * @throws SodiumException
     */
    public function testUnrolledPolynomialRoundingAndDecomposition(): void
    {
        $boundaries = array_column(self::fieldElements(), 0);
        $coefficients = [];
        for ($i = 0; $i < 256; ++$i) {
            $coefficients[$i] = $boundaries[$i % count($boundaries)];
        }
        $ring = new ParagonIE_Sodium_Core_MLDSA_Ring(...$coefficients);
        $rounded = $ring->power2Round();
        $params = new ParagonIE_Sodium_Core_MLDSA_Params();
        $high = $ring->highBits($params);
        $low = $ring->lowBits($params);
        $norm = 0;
        foreach ($coefficients as $i => $value) {
            $roundHigh = intdiv($value + 4095, 8192);
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

    public function testPrepareMessageRejectsOversizedContext(): void
    {
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Core_MLDSA_Operations::prepareMessage('message', str_repeat('c', 256));
    }
}
