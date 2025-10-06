<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(ParagonIE_Sodium_Core_Curve25519_Fe::class)]
class CoreCurve25519FeTest extends TestCase
{
    public function testConstructor(): void
    {
        $fe = new ParagonIE_Sodium_Core_Curve25519_Fe(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
        $this->assertSame(1, $fe->e0);
        $this->assertSame(10, $fe->e9);
    }

    public function testFromArray(): void
    {
        $data = array(10, 20, 30, 40, 50, 60, 70, 80, 90, 100);
        $fe = ParagonIE_Sodium_Core_Curve25519_Fe::fromArray($data);
        $this->assertInstanceOf(ParagonIE_Sodium_Core_Curve25519_Fe::class, $fe);
        $this->assertSame(10, $fe->e0);
        $this->assertSame(100, $fe->e9);
    }

    public function testFromArrayInvalid(): void
    {
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(array(1, 2, 3));
    }

    public function testArrayAccessGet(): void
    {
        $fe = new ParagonIE_Sodium_Core_Curve25519_Fe(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
        $this->assertSame(1, $fe[0]);
        $this->assertSame(5, $fe[4]);
        $this->assertSame(10, $fe[9]);
    }

    public function testArrayAccessGetInvalid(): void
    {
        $this->expectException(OutOfBoundsException::class);
        $fe = new ParagonIE_Sodium_Core_Curve25519_Fe();
        $fe[10];
    }

    public function testArrayAccessSet(): void
    {
        $fe = new ParagonIE_Sodium_Core_Curve25519_Fe();
        $fe[0] = 123;
        $fe[9] = 456;
        $this->assertSame(123, $fe[0]);
        $this->assertSame(456, $fe[9]);
    }

    public function testArrayAccessSetInvalid(): void
    {
        $this->expectException(OutOfBoundsException::class);
        $fe = new ParagonIE_Sodium_Core_Curve25519_Fe();
        $fe[10] = 1;
    }

    public function testArrayAccessExists(): void
    {
        $fe = new ParagonIE_Sodium_Core_Curve25519_Fe();
        $this->assertTrue(isset($fe[0]));
        $this->assertTrue(isset($fe[9]));
        $this->assertFalse(isset($fe[10]));
        $this->assertFalse(isset($fe[-1]));
    }

    public function testArrayAccessUnset(): void
    {
        $fe = new ParagonIE_Sodium_Core_Curve25519_Fe(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
        unset($fe[0]);
        unset($fe[9]);
        $this->assertSame(0, $fe[0]);
        $this->assertSame(0, $fe[9]);
        $this->assertSame(2, $fe[1]); // Ensure others are untouched
    }

    public function testArrayAccessUnsetInvalid(): void
    {
        $this->expectException(OutOfBoundsException::class);
        $fe = new ParagonIE_Sodium_Core_Curve25519_Fe();
        unset($fe[10]);
    }
}
