<?php

/**
 * @internal
 * @psalm-suppress PossiblyUnusedMethod
 * @implements ArrayAccess<int, int>
 */
final class ParagonIE_Sodium_Core_MLKem_RingElement extends ParagonIE_Sodium_Core_Object256 implements ArrayAccess
{
    public static function zero(): self
    {
        return new self();
    }

    /**
     * @param int[] $coefficients
     *
     * @throws SodiumException
      * @psalm-suppress PossiblyUnusedMethod
     */
    public static function fromArray(array $coefficients): self
    {
        if (count($coefficients) !== 256) {
            throw new SodiumException(
                "ParagonIE_Sodium_Core_MLKem_RingElement::fromArray() expects 256 elements"
            );
        }
        return new self(...$coefficients);
    }

    #[\Override]
    public function offsetExists(mixed $offset): bool
    {
        return $offset >= 0 && $offset < 256;
    }

    #[\Override]
    public function offsetGet(mixed $offset): int
    {
        return $this->{'c' . $offset};
    }

    #[\Override]
    public function offsetSet(mixed $offset, mixed $value): void
    {
        if ($offset === null) {
            throw new SodiumException('Cannot append to a polynomial');
        }
        $this->{'c' . $offset} = $value;
    }

    #[\Override]
    public function offsetUnset(mixed $offset): void
    {
        $this->{'c' . $offset} = 0;
    }
}
