<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\CoversClass;

/**
 * Class StreamTest
 */
#[CoversClass(ParagonIE_Sodium_Compat::class)]
class StreamTest extends TestCase
{
    /**
     * @before
     */
    #[Before]
    public function before(): void
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @throws SodiumException
     */
    public function testXChaChaStream(): void
    {
        $key = hash('sha256', 'test', true);
        $nonce = ParagonIE_Sodium_Core_Util::substr(hash('sha224', 'test', true), 0, 24);
        for ($i = 0; $i < 10; ++$i) {
            $len = random_int(1, 65535);
            $this->process($key, $nonce, $len, 'ParagonIE_Sodium_Compat::crypto_stream_xchacha20');
            $this->process(random_bytes(32), random_bytes(24), $len, 'ParagonIE_Sodium_Compat::crypto_stream_xchacha20');
        }

        $stream = ParagonIE_Sodium_Compat::crypto_stream_xchacha20(32, $nonce, $key);
        $this->assertSame(
            'f41a191e9ae71f2fc3159c14f958d37929074820e3d65504d7481edbb3c9e2cb',
            sodium_bin2hex($stream)
        );
    }

    public function testSalsaStream(): void
    {
        $key = hash('sha256', 'test', true);
        $nonce = ParagonIE_Sodium_Core_Util::substr(hash('sha224', 'test', true), 0, 24);

        for ($i = 0; $i < 10; ++$i) {
            $len = random_int(1, 65535);
            $this->process($key, $nonce, $len, 'ParagonIE_Sodium_Compat::crypto_stream');
            $this->process(random_bytes(32), random_bytes(24), $len, 'ParagonIE_Sodium_Compat::crypto_stream');
        }

        $stream = ParagonIE_Sodium_Compat::crypto_stream(32, $nonce, $key);
        $this->assertSame(
            'e16c87b630e0515e4a0f2aab3d613e3f413c07072fac3b29a101e5b562ff9fd8',
            sodium_bin2hex($stream)
        );
    }

    protected function process($key, $nonce, $len, $func = '')
    {
        $func_pieces= explode('::', $func);
        $func_xor_pieces= explode('::', $func . '_xor');
        $stream = call_user_func_array($func_pieces, array($len, $nonce, $key));
        $this->assertSame($len, ParagonIE_Sodium_Core_Util::strlen($stream));
        // Pseudorandom (but deterministic) nonce:
        $n2 = ParagonIE_Sodium_Core_Util::substr(hash('sha224', $stream, true), 0, 24);
        $encrypted = call_user_func_array($func_xor_pieces, array($stream, $n2, $key));
        $decrypted = call_user_func_array($func_xor_pieces, array($encrypted, $n2, $key));
        $this->assertSame(sodium_bin2hex($stream), sodium_bin2hex($decrypted), 'Decryption unsuccessful');
        $this->assertNotSame(sodium_bin2hex($stream), sodium_bin2hex($encrypted), 'Encryption is a NOP');
    }
}
