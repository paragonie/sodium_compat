<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(ParagonIE_Sodium_Core_Salsa20::class)]
class CoreSalsa20Test extends TestCase
{
    /**
     * @throws Exception
     * @throws SodiumException
     */
    public function testSalsa20XorReversibility(): void
    {
        $key = random_bytes(32);
        $nonce = random_bytes(8);
        $message = 'the salsa20 message';

        $encrypted = ParagonIE_Sodium_Core_Salsa20::salsa20_xor($message, $nonce, $key);
        $decrypted = ParagonIE_Sodium_Core_Salsa20::salsa20_xor($encrypted, $nonce, $key);

        $this->assertSame($message, $decrypted);
    }

    /**
     * @throws Exception
     * @throws SodiumException
     */
    public function testSalsa20XorIcReversibility(): void
    {
        $key = random_bytes(32);
        $nonce = random_bytes(8);
        $ic = random_int(0, 0xffffffff);
        $message = 'the salsa20_ic message';

        $encrypted = ParagonIE_Sodium_Core_Salsa20::salsa20_xor_ic($message, $nonce, $ic, $key);
        $decrypted = ParagonIE_Sodium_Core_Salsa20::salsa20_xor_ic($encrypted, $nonce, $ic, $key);

        $this->assertSame($message, $decrypted);
    }

    public function testSalsa20StreamVector(): void
    {
        $key = ParagonIE_Sodium_Core_Util::hex2bin(
            '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
        );
        $nonce = ParagonIE_Sodium_Core_Util::hex2bin('0001020304050607');
        $expectedStream = '2ead0f5f185729ced672b3a928e454f72fdb44a87b9cd8d219e4ec14aef9c6bc' .
            '77bf057f5659d7753848f8d3fe769ca5fdd8057d46326990e5f136e2fcb7bb7ca1';

        $stream = ParagonIE_Sodium_Core_Salsa20::salsa20(65, $nonce, $key);
        $this->assertSame(
            $expectedStream,
            ParagonIE_Sodium_Core_Util::bin2hex($stream)
        );
    }

    /**
     * @throws Exception
     * @throws SodiumException
     */
    public function testInvalidKeyLength(): void
    {
        $this->expectException(RangeException::class);
        $this->expectExceptionMessage('Key must be 32 bytes long');

        ParagonIE_Sodium_Core_Salsa20::salsa20(10, random_bytes(8), random_bytes(31));
    }
}
