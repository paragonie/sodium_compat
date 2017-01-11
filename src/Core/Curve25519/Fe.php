<?php

/**
 * Class ParagonIE_Sodium_Core_Curve25519_Fe
 *
 * This represents a Field Element
 */
class ParagonIE_Sodium_Core_Curve25519_Fe implements ArrayAccess
{
    /**
     * @var array
     */
    protected $container = array();

    /**
     * @var int
     */
    protected $size = 10;

    /**
     * ParagonIE_Sodium_Core_Curve25519_Fe constructor.
     * @param int $size
     */
    public function __construct($size = 10)
    {
        $this->size = 10;
    }

    /**
     * @param array $array
     * @param bool $save_indexes
     * @return self
     */
    public static function fromArray($array, $save_indexes = null)
    {
        $count = count($array);
        if ($save_indexes) {
            $keys = array_keys($array);
        } else {
            $keys = range(0, $count - 1);
        }
        $array = array_values($array);

        $obj = new ParagonIE_Sodium_Core_Curve25519_Fe($count);
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
     * @param mixed $offset
     * @param mixed $value
     */
    public function offsetSet($offset, $value)
    {
        if (!is_int($value)) {
            throw new InvalidArgumentException('Expected an integer');
        }
        if (is_null($offset)) {
            $this->container[] = $value;
        } else {
            $this->container[$offset] = $value;
        }
    }

    /**
     * @param mixed $offset
     * @return bool
     */
    public function offsetExists($offset)
    {
        return isset($this->container[$offset]);
    }

    /**
     * @param mixed $offset
     */
    public function offsetUnset($offset)
    {
        unset($this->container[$offset]);
    }

    /**
     * @param mixed $offset
     * @return mixed|null
     */
    public function offsetGet($offset)
    {
        return isset($this->container[$offset])
            ? $this->container[$offset]
            : null;
    }

    /**
     * @return array
     */
    public function __debugInfo()
    {
        return array(implode(', ', $this->container));
    }
}
