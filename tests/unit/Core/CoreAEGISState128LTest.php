<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(ParagonIE_Sodium_Core_AEGIS_State128L::class)]
class CoreAEGISState128LTest extends TestCase
{
    protected ParagonIE_Sodium_Core_AEGIS_State128L $state;

    public function setUp(): void
    {
        $this->state = ParagonIE_Sodium_Core_AEGIS_State128L::init(
            str_repeat("\x00", 16),
            str_repeat("\x00", 16)
        );
    }

    public function testInit(): void
    {
        $key = str_repeat("\x00", 16);
        $nonce = str_repeat("\x00", 16);
        $state = ParagonIE_Sodium_Core_AEGIS_State128L::init($key, $nonce);
        $this->assertInstanceOf(ParagonIE_Sodium_Core_AEGIS_State128L::class, $state);
    }

    /**
     * @throws SodiumException
     */
    public function testAbsorb(): void
    {
        $initialState = $this->state->getState();
        $this->state->absorb(str_repeat("\x00", 32));
        $newState = $this->state->getState();
        $this->assertNotEquals($initialState, $newState);
    }

    /**
     * @throws SodiumException
     */
    public function testEncDec(): void
    {
        $key = random_bytes(16);
        $nonce = random_bytes(16);
        $state = ParagonIE_Sodium_Core_AEGIS_State128L::init($key, $nonce);
        $state2 = ParagonIE_Sodium_Core_AEGIS_State128L::init($key, $nonce);

        $message = random_bytes(32);
        $ciphertext = $state->enc($message);
        $decrypted = $state2->dec($ciphertext);

        $this->assertSame($message, $decrypted);
    }

    /**
     * @throws SodiumException
     */
    public function testDecPartial(): void
    {
        $key = random_bytes(16);
        $nonce = random_bytes(16);
        $state = ParagonIE_Sodium_Core_AEGIS_State128L::init($key, $nonce);

        $message = random_bytes(17);
        $padded = str_pad($message, 32, "\x00", STR_PAD_RIGHT);
        $ciphertext = $state->enc($padded);
        $ciphertextPartial = substr($ciphertext, 0, 17);

        // Re-initialize state for decryption
        $state2 = ParagonIE_Sodium_Core_AEGIS_State128L::init($key, $nonce);
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
