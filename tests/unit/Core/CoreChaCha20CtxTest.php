<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
#[CoversClass(ParagonIE_Sodium_Core_ChaCha20_Ctx::class)]
class CoreChaCha20CtxTest extends TestCase
{
    /**
     * @throws SodiumException
     */
    public function testConstructor(): void
    {
        $key = random_bytes(32);
        $nonce = random_bytes(8);

        $ctx = new ParagonIE_Sodium_Core_ChaCha20_Ctx($key, $nonce);
        $this->assertInstanceOf(ParagonIE_Sodium_Core_ChaCha20_Ctx::class, $ctx);

        // Check constants
        $this->assertSame(0x61707865, $ctx[0]);
        $this->assertSame(0x3320646e, $ctx[1]);

        // Check key part
        $this->assertSame(
            ParagonIE_Sodium_Core_Util::load_4(substr($key, 0, 4)),
            $ctx[4]
        );
        $this->assertSame(
            ParagonIE_Sodium_Core_Util::load_4(substr($key, 28, 4)),
            $ctx[11]
        );

        // Check nonce part
        $this->assertSame(
            ParagonIE_Sodium_Core_Util::load_4(substr($nonce, 4, 4)),
            $ctx[15]
        );
    }

    /**
     * @throws SodiumException
     */
    public function testInvalidKeyLength(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('ChaCha20 expects a 256-bit key.');
        new ParagonIE_Sodium_Core_ChaCha20_Ctx(random_bytes(31), random_bytes(8));
    }

    /**
     * @throws SodiumException
     */
    public function testInvalidNonceLength(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('ChaCha20 expects a 64-bit nonce.');
        new ParagonIE_Sodium_Core_ChaCha20_Ctx(random_bytes(32), random_bytes(9));
    }

    /**
     * @throws SodiumException
     */
    public function testInitCounter(): void
    {
        $ctx = new ParagonIE_Sodium_Core_ChaCha20_Ctx(random_bytes(32), random_bytes(8));

        $this->assertSame(str_repeat("\0", 8), $ctx->initCounter(''));
        $this->assertSame("abc\0\0\0\0\0", $ctx->initCounter('abc'));
        $this->assertSame('12345678', $ctx->initCounter('12345678'));

        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('counter cannot be more than 8 bytes');
        $ctx->initCounter('123456789');
    }


    /**
     * @throws SodiumException
     */
    public function testArrayAccess(): void
    {
        $ctx = new ParagonIE_Sodium_Core_ChaCha20_Ctx(random_bytes(32), random_bytes(8));

        $this->assertTrue(isset($ctx[0]));
        $this->assertFalse(isset($ctx[16]));

        $ctx[12] = 999;
        $this->assertSame(999, $ctx[12]);

        unset($ctx[12]);
        $this->assertFalse(isset($ctx[12]));
        $this->assertNull($ctx[12]);
    }
}
