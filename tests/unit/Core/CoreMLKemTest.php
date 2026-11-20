<?php

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(ParagonIE_Sodium_Core_MLKem_FieldElement::class)]
#[CoversClass(ParagonIE_Sodium_Core_MLKem_Operations::class)]
#[CoversClass(ParagonIE_Sodium_Core_MLKem_RingElement::class)]
#[CoversClass(ParagonIE_Sodium_Core_MLKem_NttElement::class)]
class CoreMLKemTest extends TestCase
{
    public static function fieldPairs(): array
    {
        $cases = [];
        foreach ([0, 1, 2, 1664, 1665, 3327, 3328] as $a) {
            foreach ([0, 1, 2, 1664, 1665, 3327, 3328] as $b) {
                $cases[$a . ',' . $b] = [$a, $b];
            }
        }
        return $cases;
    }

    /**
     * @dataProvider fieldPairs
     */
    #[DataProvider('fieldPairs')]
    public function testFieldArithmetic(int $a, int $b): void
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

    public function testBarrettReductionBounds(): void
    {
        foreach ([0, 1, 3328, 3329, 3330, 6657, 3328 * 3328, 2 * 3329 * 3328] as $a) {
            $this->assertSame($a % 3329, ParagonIE_Sodium_Core_MLKem_FieldElement::reduce($a), 'Input ' . $a);
        }
        for ($a = 0; $a < 6658; ++$a) {
            $this->assertSame($a % 3329, ParagonIE_Sodium_Core_MLKem_FieldElement::reduceOnce($a), 'Input ' . $a);
        }
    }

    public static function widths(): array
    {
        return [
            'message bits' => [1],
            'v bits' => [4],
            'u bits' => [10]
        ];
    }

    /**
     * @dataProvider widths
     */
    #[DataProvider('widths')]
    public function testCompressionForEveryFieldElement(int $width): void
    {
        for ($a = 0; $a < 3329; ++$a) {
            $expected = intdiv(($a << $width) + 1664, 3329) & ((1 << $width) - 1);
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
    #[DataProvider('widths')]
    public function testDecompressionForEveryEncoding(int $width): void
    {
        for ($a = 0; $a < (1 << $width); ++$a) {
            $expected = intdiv(3329 * $a + (1 << ($width - 1)), 1 << $width);
            $this->assertSame(
                $expected,
                ParagonIE_Sodium_Core_MLKem_FieldElement::decompress($a, $width),
                'Encoding ' . $a
            );
        }
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
        $coefficients = PQPolynomialReference::coefficients(3329, $pattern);
        $ring = ParagonIE_Sodium_Core_MLKem_RingElement::fromArray($coefficients);
        $ntt = ParagonIE_Sodium_Core_MLKem_Operations::ntt($ring);
        $this->assertSame($coefficients, ParagonIE_Sodium_Core_MLKem_Operations::inverseNTT($ntt)->toArray());
        $this->assertSame($coefficients, $ring->toArray(), 'Input must not be mutated');
    }

    /**
     * @dataProvider polynomialPatterns
     */
    #[DataProvider('polynomialPatterns')]
    public function testNTTProductAgainstSchoolbookMultiplication(string $pattern): void
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

    public function testPolynomialAdditionAndSubtraction(): void
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

    public function testTwelveBitSerializationAgainstIndependentPacking(): void
    {
        $coefficients = PQPolynomialReference::coefficients(3329, 'dense');
        $expected = PQPolynomialReference::pack($coefficients, 12);
        $poly = ParagonIE_Sodium_Core_MLKem_NttElement::fromArray($coefficients);
        $this->assertSame($expected, ParagonIE_Sodium_Core_MLKem_Operations::polyByteEncode($poly));
        $this->assertSame($coefficients, ParagonIE_Sodium_Core_MLKem_Operations::polyByteDecode($expected)->toArray());
    }

    public static function noncanonicalCoefficients(): array
    {
        return [
            'first' => [0],
            'second' => [1],
            'penultimate' => [254],
            'last' => [255]
        ];
    }

    /**
     * @dataProvider noncanonicalCoefficients
     */
    #[DataProvider('noncanonicalCoefficients')]
    public function testRejectsNoncanonicalCoefficient(int $index): void
    {
        $coefficients = array_fill(0, 256, 0);
        $coefficients[$index] = 3329;
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Core_MLKem_Operations::polyByteDecode(PQPolynomialReference::pack($coefficients, 12));
    }

    public static function badPolynomialLengths(): array
    {
        return [
            'empty' => [0],
            'truncated' => [383],
            'oversized' => [385]
        ];
    }

    /**
     * @dataProvider badPolynomialLengths
     */
    #[DataProvider('badPolynomialLengths')]
    public function testRejectsIncorrectPolynomialLength(int $length): void
    {
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Core_MLKem_Operations::polyByteDecode(str_repeat("\0", $length));
    }

    /**
     * @dataProvider widths
     */
    #[DataProvider('widths')]
    public function testCompressedEncodingAgainstIndependentPacking(int $width): void
    {
        $compressed = [];
        $coefficients = [];
        for ($i = 0; $i < 256; ++$i) {
            $compressed[$i] = ($i * 769 + 511) & ((1 << $width) - 1);
            $coefficients[$i] = intdiv(3329 * $compressed[$i] + (1 << ($width - 1)), 1 << $width);
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
