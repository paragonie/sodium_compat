<?php

class SodiumCompatRistretto255Test extends KnownAnswerTestCase
{
    public function setUp(): void
    {
        if (!is_callable(array('ParagonIE_Sodium_Compat', 'ristretto255_random'))) {
            $this->markTestSkipped('Ristretto255 not supported');
        }
    }

    public function testCryptoCoreRistretto255(): void
    {
        $random = ParagonIE_Sodium_Compat::ristretto255_random();
        $this->assertSame(32, ParagonIE_Sodium_Core_Util::strlen($random));

        $hash = ParagonIE_Sodium_Compat::ristretto255_from_hash(random_bytes(64));
        $this->assertSame(32, ParagonIE_Sodium_Core_Util::strlen($hash));
    }

    /**
     * @return void
     * @throws SodiumException
     */
    public function testOperations(): void
    {
        $p = ParagonIE_Sodium_Compat::ristretto255_random();
        $q = ParagonIE_Sodium_Compat::ristretto255_random();

        $add = ParagonIE_Sodium_Compat::ristretto255_add($p, $q, true);
        $this->assertSame(32, ParagonIE_Sodium_Core_Util::strlen($add));
        $this->assertIsString($add);

        $sub = ParagonIE_Sodium_Compat::ristretto255_sub($p, $q, true);
        $this->assertSame(32, ParagonIE_Sodium_Core_Util::strlen($sub));
        $this->assertIsString($sub);

        $from_hash = ParagonIE_Sodium_Compat::ristretto255_from_hash(random_bytes(64), true);
        $this->assertSame(32, ParagonIE_Sodium_Core_Util::strlen($from_hash));
        $this->assertIsString($from_hash);

        $s_random = ParagonIE_Sodium_Compat::ristretto255_scalar_random(true);
        $this->assertSame(32, ParagonIE_Sodium_Core_Util::strlen($s_random));
        $this->assertIsString($s_random);

        $s_invert = ParagonIE_Sodium_Compat::ristretto255_scalar_invert($s_random, true);
        $this->assertSame(32, ParagonIE_Sodium_Core_Util::strlen($s_invert));
        $this->assertIsString($s_invert);

        $s_negate = ParagonIE_Sodium_Compat::ristretto255_scalar_negate($s_random, true);
        $this->assertSame(32, ParagonIE_Sodium_Core_Util::strlen($s_negate));
        $this->assertIsString($s_negate);

        $s_comp = ParagonIE_Sodium_Compat::ristretto255_scalar_complement($s_random, true);
        $this->assertSame(32, ParagonIE_Sodium_Core_Util::strlen($s_comp));
        $this->assertIsString($s_comp);

        $s_add = ParagonIE_Sodium_Compat::ristretto255_scalar_add($s_random, $s_invert, true);
        $this->assertSame(32, ParagonIE_Sodium_Core_Util::strlen($s_add));
        $this->assertIsString($s_add);

        $s_sub = ParagonIE_Sodium_Compat::ristretto255_scalar_sub($s_random, $s_invert, true);
        $this->assertSame(32, ParagonIE_Sodium_Core_Util::strlen($s_sub));
        $this->assertIsString($s_sub);

        $s_mul = ParagonIE_Sodium_Compat::ristretto255_scalar_mul($s_random, $s_invert, true);
        $this->assertSame(32, ParagonIE_Sodium_Core_Util::strlen($s_mul));
        $this->assertIsString($s_mul);

        $smult = ParagonIE_Sodium_Compat::scalarmult_ristretto255($s_random, $p, true);
        $this->assertSame(32, ParagonIE_Sodium_Core_Util::strlen($smult));
        $this->assertIsString($smult);

        $smult_base = ParagonIE_Sodium_Compat::scalarmult_ristretto255_base($s_random, true);
        $this->assertSame(32, ParagonIE_Sodium_Core_Util::strlen($smult_base));
        $this->assertIsString($smult_base);

        $s_reduce = ParagonIE_Sodium_Compat::ristretto255_scalar_reduce(random_bytes(64), true);
        $this->assertSame(32, ParagonIE_Sodium_Core_Util::strlen($s_reduce));
        $this->assertIsString($s_reduce);
    }
}
