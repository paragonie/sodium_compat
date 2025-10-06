<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(ParagonIE_Sodium_Core_AES_KeySchedule::class)]
class CoreAESKeyScheduleTest extends TestCase
{
    protected ParagonIE_Sodium_Core_AES_KeySchedule $schedule;

    public function setUp(): void
    {
        // This is a dummy schedule. The actual generation is tested in AESTest.
        $this->schedule = new ParagonIE_Sodium_Core_AES_KeySchedule(
            array_fill(0, 120, 0x1337),
            14
        );
    }

    public function testConstructorAndGetters(): void
    {
        $this->assertSame(14, $this->schedule->getNumRounds());
        $this->assertSame(0x1337, $this->schedule->get(0));
        $this->assertSame(0x1337, $this->schedule->get(119));
    }

    public function testGetRoundKey():  void
    {
        $roundKey = $this->schedule->getRoundKey(0);
        $this->assertInstanceOf(ParagonIE_Sodium_Core_AES_Block::class, $roundKey);
        $this->assertCount(8, $roundKey);
        $this->assertSame(0x1337, $roundKey[0]);
    }

    public function testExpand(): void
    {
        $expanded = $this->schedule->expand();
        $this->assertInstanceOf(ParagonIE_Sodium_Core_AES_Expanded::class, $expanded);
        $this->assertSame($this->schedule->getNumRounds(), $expanded->getNumRounds());

        // The expanded key should be different from the compact one.
        $this->assertNotEquals($this->schedule->get(0), $expanded->get(0));
    }
}
