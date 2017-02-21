<?php

class Blake2bTest extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_generichash()
     */
    public function testGenericHash()
    {
        $this->assertSame(
            pack('H*', 'df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8'),
            ParagonIE_Sodium_Compat::crypto_generichash('Paragon Initiative Enterprises, LLC'),
            'Chosen input.'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Core_BLAKE2b::update()
     */
    public function testGenericHashUpdate()
    {
        for ($h = 8; $h < 15; ++$h) {
            $hbuf = new SplFixedArray(1 << $h);
            for ($i = 0; $i < (1 << $h); ++$i) {
                $hbuf[$i] = $i & 0xff;
            }

            $buf = new SplFixedArray(1 << ($h + 1));
            for ($i = 0; $i < (1 << ($h + 1)); ++$i) {
                $buf[$i] = $i & 0xff;
            }
            $hbufStr = ParagonIE_Sodium_Core_Util::intArrayToString($hbuf->toArray());
            $this->assertSame(
                ParagonIE_Sodium_Core_Util::intArrayToString($buf->toArray()),
                $hbufStr . $hbufStr
            );

            $exp = ParagonIE_Sodium_Core_BLAKE2b::init();
            ParagonIE_Sodium_Core_BLAKE2b::update($exp, $hbuf, (1 << $h));
            ParagonIE_Sodium_Core_BLAKE2b::update($exp, $hbuf, (1 << $h));

            $ctx = ParagonIE_Sodium_Core_BLAKE2b::init();
            ParagonIE_Sodium_Core_BLAKE2b::update($ctx, $buf, (1 << ($h + 1)));
            for ($j = 0; $j < 5; ++$j) {
                $this->assertEquals($exp[$j], $ctx[$j], 'element ' . $j);
            }

            $this->assertSame(
                bin2hex(ParagonIE_Sodium_Core_BLAKE2b::contextToString($exp)),
                bin2hex(ParagonIE_Sodium_Core_BLAKE2b::contextToString($ctx)),
                'h = ' . $h);
        }
    }

    public function testCounter()
    {
        $ctx = ParagonIE_Sodium_Core_BLAKE2b::init(null, 32);

        ParagonIE_Sodium_Core_BLAKE2b::increment_counter($ctx, -1);
        ParagonIE_Sodium_Core_BLAKE2b::increment_counter($ctx, 1);
        $this->assertEquals(2, $ctx[1][0][1]);
        $this->assertEquals(0, $ctx[1][0][0]);

        $ctx = ParagonIE_Sodium_Core_BLAKE2b::init(null, 32);

        ParagonIE_Sodium_Core_BLAKE2b::increment_counter($ctx, 1);
        $this->assertEquals(1, $ctx[1][0][1]);
        $this->assertEquals(0, $ctx[1][0][0]);

        ParagonIE_Sodium_Core_BLAKE2b::increment_counter($ctx, 1);
        $this->assertEquals(2, $ctx[1][0][1]);
        $this->assertEquals(0, $ctx[1][0][0]);

        ParagonIE_Sodium_Core_BLAKE2b::increment_counter($ctx, 1024);
        $this->assertEquals(1026, $ctx[1][0][1]);
        $this->assertEquals(0, $ctx[1][0][0]);

        ParagonIE_Sodium_Core_BLAKE2b::increment_counter($ctx, 1 << 32);
        $this->assertEquals(1026, $ctx[1][0][1]);
        $this->assertEquals(1, $ctx[1][0][0]);
    }

    /**
     *
     */
    public function testContext()
    {
        $ctxA = ParagonIE_Sodium_Compat::crypto_generichash_init();
        $ctxB = ParagonIE_Sodium_Core_BLAKE2b::init(null, 32);

        $chunks = array(
            'Paragon Initiative ',
            'Enterprises, LLC',
            str_repeat("\x7e", 128),
            str_repeat("\x4d", 256),
            str_repeat("\x4e", 64),
            str_repeat("\x4f", 257),
            str_repeat("\x0a", 511)
        );
        $ctxStrB = '';
        foreach ($chunks as $i => $chk) {
            ParagonIE_Sodium_Compat::crypto_generichash_update($ctxA, $chk);
            $chunk = ParagonIE_Sodium_Core_BLAKE2b::stringToSplFixedArray($chk);
            ParagonIE_Sodium_Core_BLAKE2b::update(
                $ctxB,
                $chunk,
                $chunk->count()
            );
            $ctxStrB = ParagonIE_Sodium_Core_BLAKE2b::contextToString($ctxB);
            $this->assertEquals(
                ParagonIE_Sodium_Core_Util::bin2hex(
                    ParagonIE_Sodium_Core_Util::substr($ctxA, 0, 64)
                ),
                ParagonIE_Sodium_Core_Util::bin2hex(
                    ParagonIE_Sodium_Core_Util::substr($ctxStrB, 0, 64)
                ),
                'chunk #' . ($i + 1) . ' - 0'
            );
            $this->assertEquals(
                ParagonIE_Sodium_Core_Util::bin2hex(
                    ParagonIE_Sodium_Core_Util::substr($ctxA, 64, 32)
                ),
                ParagonIE_Sodium_Core_Util::bin2hex(
                    ParagonIE_Sodium_Core_Util::substr($ctxStrB, 64, 32)
                ),
                'chunk #' . ($i + 1) . ' - 1'
            );
            $this->assertEquals(
                ParagonIE_Sodium_Core_Util::bin2hex(
                    ParagonIE_Sodium_Core_Util::substr($ctxA, 96, 256)
                ),
                ParagonIE_Sodium_Core_Util::bin2hex(
                    ParagonIE_Sodium_Core_Util::substr($ctxStrB, 96, 256)
                ),
                'chunk #' . ($i + 1) . ' - 2'
            );
        }
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_generichash_init()
     * @covers ParagonIE_Sodium_Compat::crypto_generichash_update()
     * @covers ParagonIE_Sodium_Compat::crypto_generichash_final()
     */
    public function testGenericHashStream()
    {
        $ctx = ParagonIE_Sodium_Compat::crypto_generichash_init();
        ParagonIE_Sodium_Compat::crypto_generichash_update($ctx, 'Paragon Initiative ');
        ParagonIE_Sodium_Compat::crypto_generichash_update($ctx, 'Enterprises, LLC');
        $this->assertSame(
            'df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8',
            bin2hex(ParagonIE_Sodium_Compat::crypto_generichash_final($ctx)),
            'Chosen input.'
        );

        for ($i = 1; $i < 16; ++$i) {
            /*
            $data = random_bytes(1 << $i);
            $data2 = random_bytes(1 << $i);
            */
            $data = str_repeat("\x40", 1 << $i);
            $data2 = str_repeat("\xcf", 1 << $i);
            $hash = ParagonIE_Sodium_Compat::crypto_generichash($data . $data2);

            $out = new SplFixedArray(32);
            $ctx = ParagonIE_Sodium_Core_BLAKE2b::init(null, 32);
            ParagonIE_Sodium_Core_BLAKE2b::update($ctx, ParagonIE_Sodium_Core_BLAKE2b::stringToSplFixedArray($data), 1 << $i);
            ParagonIE_Sodium_Core_BLAKE2b::update($ctx, ParagonIE_Sodium_Core_BLAKE2b::stringToSplFixedArray($data2), 1 << $i);
            ParagonIE_Sodium_Core_BLAKE2b::finish($ctx, $out);
            $hash3 = ParagonIE_Sodium_Core_BLAKE2b::SplFixedArrayToString($out);

            $ctx = ParagonIE_Sodium_Compat::crypto_generichash_init(null, 32);
            ParagonIE_Sodium_Compat::crypto_generichash_update($ctx, $data);
            ParagonIE_Sodium_Compat::crypto_generichash_update($ctx, $data2);
            $hash2 = ParagonIE_Sodium_Compat::crypto_generichash_final($ctx);

            $this->assertSame(bin2hex($hash), bin2hex($hash3), 'Generichash streaming is failing (' . $i . ') a');
            $this->assertSame(bin2hex($hash), bin2hex($hash2), 'Generichash streaming is failing (' . $i . ') b');
        }
    }
}
