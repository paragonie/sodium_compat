<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(ParagonIE_Sodium_Core_Poly1305_state::class)]

class CorePoly1305StateTest extends TestCase
{
    public function testInvalidKeyLength(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Poly1305 requires a 32-byte key');
        new ParagonIE_Sodium_Core_Poly1305_State(random_bytes(31));
    }

    /**
     * @throws SodiumException
     */
    public function testStreamingUpdate(): void
    {
        $key = ParagonIE_Sodium_Core_Util::hex2bin('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b');
        $message = 'Cryptographic Forum Research Group';
        $expectedTag = ParagonIE_Sodium_Core_Util::hex2bin('a8061dc1305136c6c22b8baf0c0127a9');

        // Calculate hash in chunks
        $state = new ParagonIE_Sodium_Core_Poly1305_State($key);
        $state->update(substr($message, 0, 10));
        $state->update(substr($message, 10, 15));
        $state->update(substr($message, 25));
        $tag = $state->finish();

        $this->assertSame(
            ParagonIE_Sodium_Core_Util::bin2hex($expectedTag),
            ParagonIE_Sodium_Core_Util::bin2hex($tag)
        );
    }
}
