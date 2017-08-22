<?php

/**
 * Class ParagonIE_Sodium_Core32_Int64
 *
 * Encapsulates a 64-bit integer.
 *
 * These are immutable. It always returns a new instance.
 */
class ParagonIE_Sodium_Core32_Int64
{
    /** @var array<int, int> - four 16-bit integers */
    public $limbs;

    public function __construct($array = array(0, 0, 0, 0))
    {
        $this->limbs = $array;
    }

    /**
     * Adds two int64 objects
     *
     * @param ParagonIE_Sodium_Core32_Int64 $addend
     * @return ParagonIE_Sodium_Core32_Int64
     */
    public function addInt64(ParagonIE_Sodium_Core32_Int64 $addend)
    {
        $return = new ParagonIE_Sodium_Core32_Int64();
        $carry = 0;
        for ($i = 3; $i >= 0; --$i) {
            $tmp = $this->limbs[$i] + $addend->limbs[$i] + $carry;
            $carry = $tmp >> 16;
            $return->limbs[$i] = (int) ($tmp & 0xffff);
        }
        return $return;
    }

    /**
     * Adds a normal integer to an int64 object
     *
     * @param int $int
     * @return ParagonIE_Sodium_Core32_Int64
     */
    public function addInt($int)
    {
        ParagonIE_Sodium_Core32_Util::declareScalarType($int, 'int', 1);

        $return = new ParagonIE_Sodium_Core32_Int64();
        $carry = 0;
        for ($i = 3; $i > 1; --$i) {
            $tmp = $this->limbs[$i] + (($int >> ((3 - $i) << 4)) & 0xffff) + $carry;
            $carry = $tmp >> 16;
            $return->limbs[$i] = (int) ($tmp & 0xffff);
        }

        // Realistically, we shouldn't have to worry
        for ($i = 1; $i >= 0; --$i) {
            $tmp = $this->limbs[$i] + $carry;
            $carry = $tmp >> 16;
            $return->limbs[$i] = (int) ($tmp & 0xffff);
        }
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

        $i = 4;
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
     * @return ParagonIE_Sodium_Core32_Int64
     */
    public function rotateLeft($c = 0)
    {
        ParagonIE_Sodium_Core32_Util::declareScalarType($c, 'int', 1);

        $return = new ParagonIE_Sodium_Core32_Int64();
        $c &= 63;
        if ($c === 0) {
            // NOP, but we want a copy.
            $return->limbs = $this->limbs;
        } else {
            $idx_shift = ($c >> 4) & 3;
            $sub_shift = $c & 15;

            for ($i = 3; $i >= 0; --$i) {
                $j = ($i + $idx_shift) & 3;
                $k = ($i + $idx_shift + 1) & 3;
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
     * @return ParagonIE_Sodium_Core32_Int64
     */
    public function rotateRight($c = 0)
    {
        ParagonIE_Sodium_Core32_Util::declareScalarType($c, 'int', 1);

        $return = new ParagonIE_Sodium_Core32_Int64();
        $c &= 63;
        if ($c === 0) {
            // NOP, but we want a copy.
            $return->limbs = $this->limbs;
        } else {
            $idx_shift = ($c >> 4) & 3;
            $sub_shift = $c & 15;

            for ($i = 3; $i >= 0; --$i) {
                $j = ($i - $idx_shift) & 3;
                $k = ($i - $idx_shift - 1) & 3;
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
     * XOR this 64-bit integer with another.
     *
     * @param ParagonIE_Sodium_Core32_Int64 $b
     * @return ParagonIE_Sodium_Core32_Int64
     */
    public function xorInt64(ParagonIE_Sodium_Core32_Int64 $b)
    {
        $return = new ParagonIE_Sodium_Core32_Int64();
        $return->limbs = array(
            (int) ($this->limbs[0] ^ $b->limbs[0]),
            (int) ($this->limbs[1] ^ $b->limbs[1]),
            (int) ($this->limbs[2] ^ $b->limbs[2]),
            (int) ($this->limbs[3] ^ $b->limbs[3])
        );
        return $return;
    }

    /**
     * @param int $low
     * @param int $high
     * @return self
     */
    public static function fromInts($low, $high)
    {
        ParagonIE_Sodium_Core32_Util::declareScalarType($low, 'int', 1);
        ParagonIE_Sodium_Core32_Util::declareScalarType($high, 'int', 2);

        return new ParagonIE_Sodium_Core32_Int64(
            array(
                (int) (($high >> 16) & 0xffff),
                (int) ($high & 0xffff),
                (int) (($low >> 16) & 0xffff),
                (int) ($low & 0xffff)
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
        if (ParagonIE_Sodium_Core32_Util::strlen($string) !== 8) {
            throw new RangeException(
                'String must be 8 bytes; ' . ParagonIE_Sodium_Core32_Util::strlen($string) . ' given.'
            );
        }
        $return = new ParagonIE_Sodium_Core32_Int64();

        $return->limbs[0]  = (int) ((ParagonIE_Sodium_Core32_Util::chrToInt($string[0]) & 0xff) << 8);
        $return->limbs[0] |= (ParagonIE_Sodium_Core32_Util::chrToInt($string[1]) & 0xff);
        $return->limbs[1]  = (int) ((ParagonIE_Sodium_Core32_Util::chrToInt($string[2]) & 0xff) << 8);
        $return->limbs[1] |= (ParagonIE_Sodium_Core32_Util::chrToInt($string[3]) & 0xff);
        $return->limbs[2]  = (int) ((ParagonIE_Sodium_Core32_Util::chrToInt($string[4]) & 0xff) << 8);
        $return->limbs[2] |= (ParagonIE_Sodium_Core32_Util::chrToInt($string[5]) & 0xff);
        $return->limbs[3]  = (int) ((ParagonIE_Sodium_Core32_Util::chrToInt($string[6]) & 0xff) << 8);
        $return->limbs[3] |= (ParagonIE_Sodium_Core32_Util::chrToInt($string[7]) & 0xff);
        return $return;
    }

    /**
     * @return array<int, int>
     */
    public function toArray()
    {
        return array(
            (int) ($this->limbs[0] << 16 | $this->limbs[1]),
            (int) ($this->limbs[2] << 16 | $this->limbs[3])
        );
    }

    /**
     * @return string
     */
    public function toString()
    {
        return ParagonIE_Sodium_Core32_Util::intToChr(($this->limbs[0] >> 8) & 0xff) .
            ParagonIE_Sodium_Core32_Util::intToChr($this->limbs[0] & 0xff) .
            ParagonIE_Sodium_Core32_Util::intToChr(($this->limbs[1] >> 8) & 0xff) .
            ParagonIE_Sodium_Core32_Util::intToChr($this->limbs[1] & 0xff) .
            ParagonIE_Sodium_Core32_Util::intToChr(($this->limbs[2] >> 8) & 0xff) .
            ParagonIE_Sodium_Core32_Util::intToChr($this->limbs[2] & 0xff) .
            ParagonIE_Sodium_Core32_Util::intToChr(($this->limbs[3] >> 8) & 0xff) .
            ParagonIE_Sodium_Core32_Util::intToChr($this->limbs[3] & 0xff);
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->toString();
    }
}
