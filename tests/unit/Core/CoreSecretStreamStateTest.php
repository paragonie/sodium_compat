<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(ParagonIE_Sodium_Core_SecretStream_State::class)]
class CoreSecretStreamStateTest extends TestCase
{
    protected ParagonIE_Sodium_Core_SecretStream_State $state;
    protected string $key = '';
    protected string $nonce = '';

    public function setUp(): void
    {
        $this->key = random_bytes(32);
        $this->nonce = random_bytes(12);
        $this->state = new ParagonIE_Sodium_Core_SecretStream_State($this->key, $this->nonce);
    }

    public function testConstructorAndGetters(): void
    {
        $this->assertSame($this->key, $this->state->getKey());
        $this->assertSame(ParagonIE_Sodium_Core_Util::store32_le(1), $this->state->getCounter());
        $this->assertSame($this->nonce, $this->state->getNonce());
        $this->assertSame(
            ParagonIE_Sodium_Core_Util::store32_le(1) . substr($this->nonce, 0, 8),
            $this->state->getCombinedNonce()
        );
    }

    public function testIncrementCounter(): void
    {
        $this->state->incrementCounter();
        $this->assertSame(ParagonIE_Sodium_Core_Util::store32_le(2), $this->state->getCounter());
    }

    public function testCounterReset(): void
    {
        $this->state->incrementCounter()->incrementCounter();
        $this->assertSame(ParagonIE_Sodium_Core_Util::store32_le(3), $this->state->getCounter());

        $this->state->counterReset();
        $this->assertSame(ParagonIE_Sodium_Core_Util::store32_le(1), $this->state->getCounter());
    }

    /**
     * @throws Exception
     */
    public function testRekey(): void
    {
        $newKeyAndNonce = random_bytes(44); // 32-byte key + 12-byte nonce
        $this->state->rekey($newKeyAndNonce);

        $this->assertSame(substr($newKeyAndNonce, 0, 32), $this->state->getKey());
        $this->assertSame(substr($newKeyAndNonce, 32, 12), $this->state->getNonce());
    }

    /**
     * @throws Exception
     */
    public function testXorNonce(): void
    {
        $xorValue = random_bytes(8);
        $expectedNonce = ParagonIE_Sodium_Core_Util::xorStrings(
            $this->nonce,
            str_pad($xorValue, 12, "\0")
        );

        $this->state->xorNonce($xorValue);
        $this->assertSame($expectedNonce, $this->state->getNonce());
    }

    /**
     * @throws Exception
     */
    public function testNeedsRekey(): void
    {
        // Set counter to a value just before rekey is needed
        $state = new ParagonIE_Sodium_Core_SecretStream_State($this->key, $this->nonce);
        $reflection = new ReflectionClass($state);
        $counterProp = $reflection->getProperty('counter');

        // 1 left
        $counterProp->setValue($state, 0xffff - 1);
        $this->assertFalse($state->needsRekey());

        // 0 left
        $state->incrementCounter();
        $this->assertFalse($state->needsRekey());

        // -1 left, we rekey
        $state->incrementCounter();
        $this->assertTrue($state->needsRekey());
    }

    public function testSerialization(): void
    {
        $this->state->incrementCounter()->incrementCounter(); // Change state
        $serialized = $this->state->toString();
        $deserialized = ParagonIE_Sodium_Core_SecretStream_State::fromString($serialized);

        $this->assertEquals($this->state, $deserialized);
        $this->assertSame($this->state->getKey(), $deserialized->getKey());
        $this->assertSame($this->state->getCounter(), $deserialized->getCounter());
        $this->assertSame($this->state->getNonce(), $deserialized->getNonce());
    }
}