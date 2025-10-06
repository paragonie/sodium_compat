<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(ParagonIE_Sodium_Core_AES_Block::class)]
class CoreAESBlockTest extends TestCase
{
    protected ParagonIE_Sodium_Core_AES_Block $block;

    public function setUp(): void
    {
        // Use a non-zero, non-repeating pattern for testing
        $this->block = ParagonIE_Sodium_Core_AES_Block::fromArray(
            array(
                0x01234567, 0x89abcdef,
                0xfedcba98, 0x76543210,
                0xdeadbeef, 0xcafebabe,
                0xfaceb00c, 0x1337c0de
            )
        );
    }

    public function testInit(): void
    {
        $block = ParagonIE_Sodium_Core_AES_Block::init();
        $this->assertInstanceOf(ParagonIE_Sodium_Core_AES_Block::class, $block);
        $this->assertSame(8, count($block));
        for ($i = 0; $i < 8; ++$i) {
            $this->assertSame(0, $block[$i]);
        }
    }

    public function testFromArray(): void
    {
        $data = [1, 2, 3, 4, 5, 6, 7, 8];
        $block = ParagonIE_Sodium_Core_AES_Block::fromArray($data);
        for ($i = 0; $i < 8; ++$i) {
            $this->assertSame($data[$i], $block[$i]);
        }
    }

    public function testArrayAccess(): void
    {
        $block = ParagonIE_Sodium_Core_AES_Block::init();
        $this->assertFalse(isset($block[8]));

        $block[0] = 123;
        $this->assertArrayHasKey(0, $block);
        $this->assertSame(123, $block[0]);

        unset($block[0]);
        $this->assertArrayNotHasKey(0, $block);
    }

    public function testOrthogonalizeIsReversible(): void
    {
        $original = clone $this->block;
        $this->block->orthogonalize();
        $this->assertNotEquals($original->toArray(), $this->block->toArray());

        $this->block->orthogonalize();
        $this->assertEquals($original->toArray(), $this->block->toArray());
    }

    public function testShiftRowsIsReversible()
    {
        $original = clone $this->block;
        $this->block->shiftRows();
        $this->assertNotEquals($original->toArray(), $this->block->toArray());

        $this->block->inverseShiftRows();
        $this->assertEquals($original->toArray(), $this->block->toArray());
    }

    public function testMixColumnsIsReversible()
    {
        $original = clone $this->block;
        $this->block->mixColumns();
        $this->assertNotEquals($original->toArray(), $this->block->toArray());

        $this->block->inverseMixColumns();
        $this->assertEquals($original->toArray(), $this->block->toArray());
    }

    public function testRotr16()
    {
        $value = 0x12345678;
        $rotated = ParagonIE_Sodium_Core_AES_Block::rotr16($value);
        $this->assertSame(0x56781234, $rotated);

        $rotated2 = ParagonIE_Sodium_Core_AES_Block::rotr16($rotated);
        $this->assertSame($value, $rotated2);
    }
}
