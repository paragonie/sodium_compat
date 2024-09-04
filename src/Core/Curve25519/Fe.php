<?php
declare(strict_types=1);

if (class_exists('ParagonIE_Sodium_Core_Curve25519_Fe', false)) {
    return;
}

/**
 * Class ParagonIE_Sodium_Core_Curve25519_Fe
 *
 * This represents a Field Element
 *
 * @psalm-suppress MissingTemplateParam
 */
class ParagonIE_Sodium_Core_Curve25519_Fe implements ArrayAccess
{
    /**
     * @var array<int, int>
     */
    protected array $container = [];

    /**
     * @var int
     */
    protected int $size = 10;

    /**
     * @internal You should not use this directly from another application
     *
     * @param array<int, int> $array
     * @param bool $save_indexes
     * @return self
     */
    public static function fromArray(array $array, bool $save_indexes = false): self
    {
        $count = count($array);
        if ($save_indexes) {
            $keys = array_keys($array);
        } else {
            $keys = range(0, $count - 1);
        }
        $array = array_values($array);
        /** @var array<int, int> $keys */

        $obj = new ParagonIE_Sodium_Core_Curve25519_Fe();
        if ($save_indexes) {
            for ($i = 0; $i < $count; ++$i) {
                $obj->offsetSet($keys[$i], $array[$i]);
            }
        } else {
            for ($i = 0; $i < $count; ++$i) {
                $obj->offsetSet($i, $array[$i]);
            }
        }
        return $obj;
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param int|null $offset
     * @param int $value
     * @return void
     */
    #[ReturnTypeWillChange]
    public function offsetSet($offset, $value): void
    {
        if (is_null($offset)) {
            $this->container[] = $value;
        } else {
            $this->container[$offset] = $value;
        }
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param int $offset
     * @return bool
     */
    #[ReturnTypeWillChange]
    public function offsetExists($offset): bool
    {
        return isset($this->container[$offset]);
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param int $offset
     * @return void
     */
    #[ReturnTypeWillChange]
    public function offsetUnset($offset): void
    {
        unset($this->container[$offset]);
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param int $offset
     * @return int
     * @psalm-suppress ImplementedReturnTypeMismatch
     */
    #[ReturnTypeWillChange]
    public function offsetGet($offset): int
    {
        if (!isset($this->container[$offset])) {
            $this->container[$offset] = 0;
        }
        return $this->container[$offset];
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @return array
     */
    public function __debugInfo()
    {
        return array(implode(', ', $this->container));
    }
}
