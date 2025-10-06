<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(ParagonIE_Sodium_Core_AEGIS_State256::class)]

class CoreAEGISState256Test extends TestCase
{
    protected ParagonIE_Sodium_Core_AEGIS_State256 $state;

    public function setUp(): void
    {
        $this->state = ParagonIE_Sodium_Core_AEGIS_State256::init(
            str_repeat("\x00", 32),
            str_repeat("\x00", 32)
        );
    }

    public function testInit(): void
    {
        $key = str_repeat("\x00", 32);
        $nonce = str_repeat("\x00", 32);
        $state = ParagonIE_Sodium_Core_AEGIS_State256::init($key, $nonce);
        $this->assertInstanceOf(ParagonIE_Sodium_Core_AEGIS_State256::class, $state);
    }

    /**
     * @throws SodiumException
     */
    public function testAbsorb(): void
    {
        $initialState = $this->state->getState();
        $this->state->absorb(str_repeat("\x00", 16));
        $newState = $this->state->getState();
        $this->assertNotEquals($initialState, $newState);
    }

    /**
     * @throws SodiumException
     * @throws Exception
     */
    public function testEncDec(): void
    {
        $key = random_bytes(32);
        $nonce = random_bytes(32);
        $state = ParagonIE_Sodium_Core_AEGIS_State256::init($key, $nonce);
        $state2 = ParagonIE_Sodium_Core_AEGIS_State256::init($key, $nonce);

        $message = random_bytes(16);
        $ciphertext = $state->enc($message);
        $decrypted = $state2->dec($ciphertext);

        $this->assertSame($message, $decrypted);
    }

    /**
     * @throws Exception
     * @throws SodiumException
     */
    public function testDecPartial(): void
    {
        $key = random_bytes(32);
        $nonce = random_bytes(32);
        $state = ParagonIE_Sodium_Core_AEGIS_State256::init($key, $nonce);

        $message = random_bytes(9);
        $padded = str_pad($message, 16, "\x00", STR_PAD_RIGHT);
        $ciphertext = $state->enc($padded);
        $ciphertextPartial = substr($ciphertext, 0, 9);

        // Re-initialize state for decryption
        $state2 = ParagonIE_Sodium_Core_AEGIS_State256::init($key, $nonce);
        $decryptedPartial = $state2->decPartial($ciphertextPartial);

        $this->assertSame($message, $decryptedPartial);
    }

    public function testFinalize(): void
    {
        $tag = $this->state->finalize(0, 0);
        $this->assertIsString($tag);
        $this->assertSame(32, strlen($tag));
    }
}