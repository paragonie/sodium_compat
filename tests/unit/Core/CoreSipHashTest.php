<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(ParagonIE_Sodium_Core_SipHash::class)]

class CoreSipHashTest extends TestCase
{
    public function testAdd(): void
    {
        // Simple addition
        $a = array(0, 1);
        $b = array(0, 2);
        $sum = ParagonIE_Sodium_Core_SipHash::add($a, $b);
        $this->assertSame(array(0, 3), $sum);

        // Test carry
        $a = array(0, 0xffffffff);
        $b = array(0, 1);
        $sum = ParagonIE_Sodium_Core_SipHash::add($a, $b);
        $this->assertSame(array(1, 0), $sum);

        // Test with high part
        $a = array(1, 0xffffffff);
        $b = array(1, 1);
        $sum = ParagonIE_Sodium_Core_SipHash::add($a, $b);
        $this->assertSame(array(3, 0), $sum);
    }

    public function testRotl64(): void
    {
        $v0 = 0x12345678;
        $v1 = 0x9abcdef0;

        // Rotate by 0
        list($r0, $r1) = ParagonIE_Sodium_Core_SipHash::rotl_64($v0, $v1, 0);
        $this->assertSame($v0, $r0);
        $this->assertSame($v1, $r1);

        // Rotate by 32
        list($r0, $r1) = ParagonIE_Sodium_Core_SipHash::rotl_64($v0, $v1, 32);
        $this->assertSame($v1, $r0);
        $this->assertSame($v0, $r1);

        // Rotate by 13
        list($r0, $r1) = ParagonIE_Sodium_Core_SipHash::rotl_64($v0, $v1, 13);
        $this->assertSame(0x8acf1357, $r0);
        $this->assertSame(0x9bde0246, $r1);
    }

    /**
     * @dataProvider provideSipHashVectors
     */
    #[DataProvider("provideSipHashVectors")]
    public function testSipHash24($expected, $message, $key)
    {
        $this->assertSame(
            $expected,
            ParagonIE_Sodium_Core_Util::bin2hex(
                ParagonIE_Sodium_Core_SipHash::sipHash24(
                    ParagonIE_Sodium_Core_Util::hex2bin($message),
                    ParagonIE_Sodium_Core_Util::hex2bin($key)
                )
            )
        );
    }

    /**
     * @see https://www.aumasson.jp/siphash/siphash.pdf
     */
    public static function provideSipHashVectors(): array
    {
        $key = '000102030405060708090a0b0c0d0e0f';
        return array(
            // 0-byte message
            array('310e0edd47db6f72', '', $key),
            // 1-byte message
            array('fd67dc93c539f874', '00', $key),
            // 7-byte message
            array('37d1018bf50002ab', '00010203040506', $key),
            // 8-byte message
            array('6224939a79f5f593', '0001020304050607', $key),
            // 15-byte message (from paper)
            array('e545be4961ca29a1', '000102030405060708090a0b0c0d0e', $key),
            // 16-byte message
            array('db9bc2577fcc2a3f', '000102030405060708090a0b0c0d0e0f', $key)
        );
    }
}
