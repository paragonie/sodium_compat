<?php

/**
 * Class ParagonIE_Sodium_Core32_Int32
 *
 * Encapsulates a 32-bit integer.
 *
 * These are immutable. It always returns a new instance.
 */
class ParagonIE_Sodium_Core32_Int32
{
    /** @var array<int, int> - two 16-bit integers */
    public $limbs;

    public function __construct($array = array(0, 0))
    {
        $this->limbs = $array;
    }

    /**
     * Adds two int32 objects
     *
     * @param ParagonIE_Sodium_Core32_Int32 $addend
     * @return ParagonIE_Sodium_Core32_Int32
     */
    public function addInt32(ParagonIE_Sodium_Core32_Int32 $addend)
    {
        $return = new ParagonIE_Sodium_Core32_Int32();

        $tmp = $this->limbs[1] + $addend->limbs[1];
        $carry = $tmp >> 16;
        $return->limbs[1] = (int) ($tmp & 0xffff);

        $tmp = $this->limbs[0] + $addend->limbs[0] + $carry;
        $return->limbs[0] = (int) ($tmp & 0xffff);

        return $return;
    }

    /**
     * Adds a normal integer to an int32 object
     *
     * @param int $int
     * @return ParagonIE_Sodium_Core32_Int32
     */
    public function addInt($int)
    {
        ParagonIE_Sodium_Core32_Util::declareScalarType($int, 'int', 1);

        $return = new ParagonIE_Sodium_Core32_Int32();

        $tmp = $this->limbs[1] + ($int & 0xffff);
        $carry = $tmp >> 16;
        $return->limbs[1] = (int) ($tmp & 0xffff);

        $tmp = $this->limbs[0] + (($int >> 16) & 0xffff) + $carry;
        $return->limbs[0] = (int) ($tmp & 0xffff);
        return $return;
    }

    /**
     * @param int $b
     * @return int
     */
    public function compareInt($b = 0)
    {
        $gt = 0;
        $eq = 1;

        $i = 2;
        $j = 0;
        while ($i > 0) {
            --$i;
            $x1 = $this->limbs[$i];
            $x2 = ($b >> ($j << 4)) & 0xffff;
            $gt |= (($x2 - $x1) >> 8) & $eq;
            $eq &= (($x2 ^ $x1) - 1) >> 8;
        }
        return ($gt + $gt - $eq) + 1;
    }

    /**
     * @param int $b
     * @return bool
     */
    public function isLessThanInt($b = 0)
    {
        return $this->compareInt($b) < 0;
    }

    /**
     * @param int $c
     * @return ParagonIE_Sodium_Core32_Int32
     */
    public function rotateLeft($c = 0)
    {
        ParagonIE_Sodium_Core32_Util::declareScalarType($c, 'int', 1);

        $return = new ParagonIE_Sodium_Core32_Int32();
        $c &= 31;
        if ($c === 0) {
            // NOP, but we want a copy.
            $return->limbs = $this->limbs;
        } else {
            $idx_shift = ($c >> 4) & 1;
            $sub_shift = $c & 15;

            for ($i = 1; $i >= 0; --$i) {
                $j = ($i + $idx_shift) & 1;
                $k = ($i + $idx_shift + 1) & 1;
                $return->limbs[$i] = (int) (
                    (
                        ($this->limbs[$j] << $sub_shift)
                            |
                        ($this->limbs[$k] >> (16 - $sub_shift))
                    ) & 0xffff
                );
            }
        }
        return $return;
    }

    /**
     * Rotate to the right
     *
     * @param int $c
     * @return ParagonIE_Sodium_Core32_Int32
     */
    public function rotateRight($c = 0)
    {
        ParagonIE_Sodium_Core32_Util::declareScalarType($c, 'int', 1);

        $return = new ParagonIE_Sodium_Core32_Int32();
        $c &= 31;
        if ($c === 0) {
            // NOP, but we want a copy.
            $return->limbs = $this->limbs;
        } else {
            $idx_shift = ($c >> 4) & 1;
            $sub_shift = $c & 15;

            for ($i = 1; $i >= 0; --$i) {
                $j = ($i - $idx_shift) & 1;
                $k = ($i - $idx_shift - 1) & 1;
                $return->limbs[$i] = (int) (
                    (
                        ($this->limbs[$j] >> ($sub_shift))
                            |
                        ($this->limbs[$k] << (16 - $sub_shift))
                    ) & 0xffff
                );
            }
        }
        return $return;
    }

    /**
     * XOR this 32-bit integer with another.
     *
     * @param ParagonIE_Sodium_Core32_Int32 $b
     * @return ParagonIE_Sodium_Core32_Int32
     */
    public function xorInt32(ParagonIE_Sodium_Core32_Int32 $b)
    {
        $return = new ParagonIE_Sodium_Core32_Int32();
        $return->limbs = array(
            (int) ($this->limbs[0] ^ $b->limbs[0]),
            (int) ($this->limbs[1] ^ $b->limbs[1])
        );
        return $return;
    }

    /**
     * @param int $signed
     * @return self
     */
    public static function fromInt($signed)
    {
        ParagonIE_Sodium_Core32_Util::declareScalarType($signed, 'int', 1);;

        return new ParagonIE_Sodium_Core32_Int32(
            array(
                (int) (($signed >> 16) & 0xffff),
                (int) ($signed & 0xffff)
            )
        );
    }

    /**
     * @param string $string
     * @return self
     */
    public static function fromString($string)
    {
        ParagonIE_Sodium_Core32_Util::declareScalarType($string, 'string', 1);
        $string = (string) $string;
        if (ParagonIE_Sodium_Core32_Util::strlen($string) !== 4) {
            throw new RangeException(
                'String must be 4 bytes; ' . ParagonIE_Sodium_Core32_Util::strlen($string) . ' given.'
            );
        }
        $return = new ParagonIE_Sodium_Core32_Int32();

        $return->limbs[0]  = (int) ((ParagonIE_Sodium_Core32_Util::chrToInt($string[0]) & 0xff) << 8);
        $return->limbs[0] |= (ParagonIE_Sodium_Core32_Util::chrToInt($string[1]) & 0xff);
        $return->limbs[1]  = (int) ((ParagonIE_Sodium_Core32_Util::chrToInt($string[2]) & 0xff) << 8);
        $return->limbs[1] |= (ParagonIE_Sodium_Core32_Util::chrToInt($string[3]) & 0xff);
        return $return;
    }

    /**
     * @param string $string
     * @return self
     */
    public static function fromReverseString($string)
    {
        ParagonIE_Sodium_Core32_Util::declareScalarType($string, 'string', 1);
        $string = (string) $string;
        if (ParagonIE_Sodium_Core32_Util::strlen($string) !== 4) {
            throw new RangeException(
                'String must be 4 bytes; ' . ParagonIE_Sodium_Core32_Util::strlen($string) . ' given.'
            );
        }
        $return = new ParagonIE_Sodium_Core32_Int32();

        $return->limbs[0]  = (int) ((ParagonIE_Sodium_Core32_Util::chrToInt($string[3]) & 0xff) << 8);
        $return->limbs[0] |= (ParagonIE_Sodium_Core32_Util::chrToInt($string[2]) & 0xff);
        $return->limbs[1]  = (int) ((ParagonIE_Sodium_Core32_Util::chrToInt($string[1]) & 0xff) << 8);
        $return->limbs[1] |= (ParagonIE_Sodium_Core32_Util::chrToInt($string[0]) & 0xff);
        return $return;
    }

    /**
     * @return array<int, int>
     */
    public function toArray()
    {
        return array((int) ($this->limbs[0] << 16 | $this->limbs[1]));
    }

    /**
     * @return string
     */
    public function toString()
    {
        return
            ParagonIE_Sodium_Core32_Util::intToChr(($this->limbs[0] >> 8) & 0xff) .
            ParagonIE_Sodium_Core32_Util::intToChr($this->limbs[0] & 0xff) .
            ParagonIE_Sodium_Core32_Util::intToChr(($this->limbs[1] >> 8) & 0xff) .
            ParagonIE_Sodium_Core32_Util::intToChr($this->limbs[1] & 0xff);
    }

    /**
     * @return string
     */
    public function toReverseString()
    {
        return ParagonIE_Sodium_Core32_Util::intToChr($this->limbs[1] & 0xff) .
            ParagonIE_Sodium_Core32_Util::intToChr(($this->limbs[1] >> 8) & 0xff) .
            ParagonIE_Sodium_Core32_Util::intToChr($this->limbs[0] & 0xff) .
            ParagonIE_Sodium_Core32_Util::intToChr(($this->limbs[0] >> 8) & 0xff);
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->toString();
    }
}
