<?php

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(ParagonIE_Sodium_Core_Object256::class)]
class CoreObject256Test extends TestCase
{
    public static function containers(): array
    {
        return [
            'ML-KEM ring' => [ParagonIE_Sodium_Core_MLKem_RingElement::class],
            'ML-KEM NTT' => [ParagonIE_Sodium_Core_MLKem_NttElement::class],
            'ML-DSA ring' => [ParagonIE_Sodium_Core_MLDSA_Ring::class],
            'ML-DSA NTT' => [ParagonIE_Sodium_Core_MLDSA_Ntt::class]
        ];
    }

    /**
     * @dataProvider containers
     */
    #[DataProvider('containers')]
    public function testCoefficientOrderAndCloneIsolation(string $class): void
    {
        $coefficients = range(0, 255);
        $poly = new $class(...$coefficients);
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
    #[DataProvider('containers')]
    public function testZeroAndOffsetBounds(string $class): void
    {
        $poly = $class::zero();
        $this->assertSame(array_fill(0, 256, 0), $poly->toArray());
        $this->assertFalse(isset($poly[-1]));
        $this->assertTrue(isset($poly[0]));
        $this->assertTrue(isset($poly[255]));
        $this->assertFalse(isset($poly[256]));
    }

    /**
     * @dataProvider containers
     */
    #[DataProvider('containers')]
    public function testAppendingToFixedSizePolynomialIsRejected(string $class): void
    {
        $poly = new $class();
        $this->expectException(SodiumException::class);
        $poly[] = 1;
    }
}
