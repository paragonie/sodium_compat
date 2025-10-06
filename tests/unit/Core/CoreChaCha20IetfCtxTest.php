<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
#[CoversClass(ParagonIE_Sodium_Core_ChaCha20_IetfCtx::class)]
class CoreChaCha20IetfCtxTest extends TestCase
{
    /**
     * @throws Exception
     * @throws SodiumException
     */
    public function testConstructor(): void
    {
        $key = random_bytes(32);
        $nonce = random_bytes(12);
        $counter = ParagonIE_Sodium_Core_Util::store32_le(12345);

        $ctx = new ParagonIE_Sodium_Core_ChaCha20_IetfCtx($key, $nonce, $counter);
        $this->assertInstanceOf(ParagonIE_Sodium_Core_ChaCha20_IetfCtx::class, $ctx);

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

        // Check counter and nonce parts (IETF layout)
        $this->assertSame(12345, $ctx[12]);
        $this->assertSame(
            ParagonIE_Sodium_Core_Util::load_4(substr($nonce, 0, 4)),
            $ctx[13]
        );
        $this->assertSame(
            ParagonIE_Sodium_Core_Util::load_4(substr($nonce, 4, 4)),
            $ctx[14]
        );
        $this->assertSame(
            ParagonIE_Sodium_Core_Util::load_4(substr($nonce, 8, 4)),
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
        new ParagonIE_Sodium_Core_ChaCha20_IetfCtx(random_bytes(31), random_bytes(12));
    }

    /**
     * @throws SodiumException
     */
    public function testInvalidNonceLength(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('ChaCha20 expects a 96-bit nonce in IETF mode.');
        new ParagonIE_Sodium_Core_ChaCha20_IetfCtx(random_bytes(32), random_bytes(11));
    }
}
