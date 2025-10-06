<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
#[CoversClass(ParagonIE_Sodium_Core_BLAKE2b::class)]
class CoreBLAKE2bTest extends TestCase
{
    public function setUp(): void
    {
        ParagonIE_Sodium_Core_BLAKE2b::pseudoConstructor();
    }

    public function testAdd64(): void
    {
        $x = ParagonIE_Sodium_Core_BLAKE2b::new64(0, 1);
        $y = ParagonIE_Sodium_Core_BLAKE2b::new64(0, 2);
        $sum = ParagonIE_Sodium_Core_BLAKE2b::add64($x, $y);
        $this->assertSame(0, $sum[0]);
        $this->assertSame(3, $sum[1]);

        // Test carry
        $x = ParagonIE_Sodium_Core_BLAKE2b::new64(0, 0xffffffff);
        $y = ParagonIE_Sodium_Core_BLAKE2b::new64(0, 1);
        $sum = ParagonIE_Sodium_Core_BLAKE2b::add64($x, $y);
        $this->assertSame(1, $sum[0]);
        $this->assertSame(0, $sum[1]);
    }

    /**
     * @throws SodiumException
     */
    public function testXor64(): void
    {
        $x = ParagonIE_Sodium_Core_BLAKE2b::new64(0x12345678, 0x9abcdef0);
        $y = ParagonIE_Sodium_Core_BLAKE2b::new64(0xfedcba98, 0x76543210);
        $xored = ParagonIE_Sodium_Core_BLAKE2b::xor64($x, $y);
        $this->assertSame(0xece8ece0, $xored[0]); // 0x12345678 ^ 0xfedcba98
        $this->assertSame(0xece8ece0, $xored[1]);
    }

    /**
     * @throws SodiumException
     */
    public function testRotr64(): void
    {
        $x = ParagonIE_Sodium_Core_BLAKE2b::new64(0x12345678, 0x9abcdef0);

        // Rotate by 0
        $r0 = ParagonIE_Sodium_Core_BLAKE2b::rotr64(clone $x, 0);
        $this->assertSame(0x12345678, $r0[0]);
        $this->assertSame(0x9abcdef0, $r0[1]);

        // Rotate by 8
        $r8 = ParagonIE_Sodium_Core_BLAKE2b::rotr64(clone $x, 8);
        $this->assertSame(0xf0123456, $r8[0]);
        $this->assertSame(0x789abcde, $r8[1]);

        // Rotate by 16
        $r16 = ParagonIE_Sodium_Core_BLAKE2b::rotr64(clone $x, 16);
        $this->assertSame(0xdef01234, $r16[0]);
        $this->assertSame(0x56789abc, $r16[1]);

        // Rotate by 24
        $r24 = ParagonIE_Sodium_Core_BLAKE2b::rotr64(clone $x, 24);
        $this->assertSame(0xbcdef012, $r24[0]);
        $this->assertSame(0x3456789a, $r24[1]);

        // Rotate by 32
        $r32 = ParagonIE_Sodium_Core_BLAKE2b::rotr64(clone $x, 32);
        $this->assertSame(0x9abcdef0, $r32[0]);
        $this->assertSame(0x12345678, $r32[1]);

        // Rotate by 40
        $r40 = ParagonIE_Sodium_Core_BLAKE2b::rotr64(clone $x, 40);
        $this->assertSame(0x789abcde, $r40[0]);
        $this->assertSame(0xf0123456, $r40[1]);

        // Rotate by 64
        $r64 = ParagonIE_Sodium_Core_BLAKE2b::rotr64(clone $x, 64);
        $this->assertSame(0x12345678, $r64[0]);
        $this->assertSame(0x9abcdef0, $r64[1]);
    }

    /**
     * @see https://tools.ietf.org/html/rfc7693#section-4.1
     */
    public function testRfc7693Vector1(): void
    {
        $input = 'abc';
        $expected = 'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1' .
            '7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923';

        $ctx = ParagonIE_Sodium_Core_BLAKE2b::init(null, 64);
        ParagonIE_Sodium_Core_BLAKE2b::update(
            $ctx,
            ParagonIE_Sodium_Core_BLAKE2b::stringToSplFixedArray($input),
            strlen($input)
        );
        $final = new SplFixedArray(64);
        ParagonIE_Sodium_Core_BLAKE2b::finish($ctx, $final);

        $this->assertSame(
            $expected,
            ParagonIE_Sodium_Core_Util::bin2hex(
                ParagonIE_Sodium_Core_BLAKE2b::SplFixedArrayToString($final)
            )
        );
    }

    /**
     * @throws SodiumException
     */
    public function testStreaming(): void
    {
        $input1 = 'The quick brown fox ';
        $input2 = 'jumps over the lazy dog';
        $fullInput = $input1 . $input2;

        // Calculate hash of full message at once
        $ctx1 = ParagonIE_Sodium_Core_BLAKE2b::init(null, 64);
        ParagonIE_Sodium_Core_BLAKE2b::update($ctx1, ParagonIE_Sodium_Core_BLAKE2b::stringToSplFixedArray($fullInput), strlen($fullInput));
        $final1 = ParagonIE_Sodium_Core_BLAKE2b::finish($ctx1, new SplFixedArray(64));
        $hash1 = ParagonIE_Sodium_Core_Util::bin2hex(
            ParagonIE_Sodium_Core_BLAKE2b::SplFixedArrayToString($final1)
        );

        // Calculate hash in chunks
        $ctx2 = ParagonIE_Sodium_Core_BLAKE2b::init(null, 64);
        ParagonIE_Sodium_Core_BLAKE2b::update($ctx2, ParagonIE_Sodium_Core_BLAKE2b::stringToSplFixedArray($input1), strlen($input1));
        ParagonIE_Sodium_Core_BLAKE2b::update($ctx2, ParagonIE_Sodium_Core_BLAKE2b::stringToSplFixedArray($input2), strlen($input2));
        $final2 = ParagonIE_Sodium_Core_BLAKE2b::finish($ctx2, new SplFixedArray(64));
        $hash2 = ParagonIE_Sodium_Core_Util::bin2hex(
            ParagonIE_Sodium_Core_BLAKE2b::SplFixedArrayToString($final2)
        );

        $this->assertSame($hash1, $hash2);
    }
}
