<?php

class Blake2bTest extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_generichash()
     *
     * @throws SodiumException
     * @throws TypeError
     */
    public function testGenericHash()
    {
        $this->assertSame(
            'df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8',
            ParagonIE_Sodium_Core_Util::bin2hex(
                ParagonIE_Sodium_Compat::crypto_generichash('Paragon Initiative Enterprises, LLC')
            ),
            'Chosen input.'
        );
    }

    /**
     * @throws SodiumException
     */
    public function testPersonalizedState()
    {
        $exp = ParagonIE_Sodium_Core_Util::hex2bin(
            '48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5e4e0d0cf4b636b35260e0d1fbf0e60ab' .
            '5e8c73cdcdbbb17e4a164a2329a9d23a0000000000000000000000000000000000000000000000000000000000000000' .
            '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' .
            '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' .
            '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' .
            '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' .
            '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' .
            '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        );

        $k = '';
        $salt = '5b6b41ed9b343fe0';
        $personal = '5126fb2a37400d2a';

        for ($h = 0; $h < 64; ++$h) {
            $k[$h] = ParagonIE_Sodium_Core_Util::intToChr($h);
        }

        $state = ParagonIE_Sodium_Compat::crypto_generichash_init_salt_personal('', 64, $salt, $personal);

        // Chop off last 17 bytes if present because they'll throw off tests:
        $a = ParagonIE_Sodium_Core_Util::substr($state, 0, 361);
        $b = ParagonIE_Sodium_Core_Util::substr($exp, 0, 361);
        $this->assertEquals(
            ParagonIE_Sodium_Core_Util::bin2hex($b),
            ParagonIE_Sodium_Core_Util::bin2hex($a),
            'Initialized value is incorrect'
        );

        $in = '';

        for ($i = 0; $i < 64; ++$i) {
            $in .= ParagonIE_Sodium_Core_Util::intToChr($i);
        }
        ParagonIE_Sodium_Compat::crypto_generichash_update($state, $in);

        $exp2 = ParagonIE_Sodium_Core_Util::hex2bin(
            '48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5e4e0d0cf4b636b35260e0d1fbf0e60ab' .
            '5e8c73cdcdbbb17e4a164a2329a9d23a0000000000000000000000000000000000000000000000000000000000000000' .
            '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f' .
            '303132333435363738393a3b3c3d3e3f0000000000000000000000000000000000000000000000000000000000000000' .
            '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' .
            '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' .
            '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' .
            '000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000'
        );

        // Chop off last 17 bytes if present because they'll throw off tests:
        $a = ParagonIE_Sodium_Core_Util::substr($state, 0, 361);
        $b = ParagonIE_Sodium_Core_Util::substr($exp2, 0, 361);
        $this->assertEquals(
            ParagonIE_Sodium_Core_Util::bin2hex($b),
            ParagonIE_Sodium_Core_Util::bin2hex($a),
            'Updated value is incorrect'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_generichash()
     *
     * @throws SodiumException
     * @throws TypeError
     */
    public function testGenericHashSaltPersonal()
    {
        $outputs = array(
            'ba',
            '6139',
            '3a1666',
            '5797e9d0',
            '834a26efe6',
            'd7e9e862bbce',
            '40d8b84c374750',
            '276789189244cf04',
            '16f73ffe0673cc9992',
            'b3835bfaf6eb71d94078',
            '8c624e844d34f4a59f34cc',
            'e0a394962413ad09975df3cf',
            '47f043c3aacb501f97e0458ae3',
            'b4a11f2fb72a7e6f96fdacf98d49',
            'f434079e9adeb244047cb6855f9854',
            '5fbe885c4b2d4e0d78dc5905622a277a',
            'e262ba3e2ab76efdf83513108e3b987d1b',
            'add93dde78d32e77bc039c34a49043f19d26',
            '093842ac10e2eb1237ddc9ca9e7990cf397772',
            '09e7f6a0e2ea4888f1dbf6562effd1561c65029c',
            'bd33a9ec914f5b81864a49184338e4062d6c6b2b2e',
            '8dc46295235d94f5881d429a5ad47f9db9e35cf8c6b3',
            'ba5df554dca7ac1cba4889fa88adf3070fbf4ab5d187b5',
            '1ff84715e71c66214d271d421395fb6166db97b1d47ed697',
            '75a0d227c70549f5b0c933b7b21f151355bd47e04b6085c91f',
            'a32a5c9439a0fa771dcbe7f338b5dcef62a754edc4952614d6f0',
            '53a87de519cdcc7f64730d58bce6baaf7b44c5c428a4611a208ad4',
            '5e5ad8f0c4f083f9b7a5154d9c0dfd0f3d2fce94cf54fc215450314a',
            '9c76b9e63c77e6564b1e5111c2fb140046e1e5a4f900a7cfc2bac3fcfa',
            'bb919251ca310eb9b994e5d7883bc9fa2144b59b8d5d940677b7130ac777',
            'faa492a66f08ef0c7adb868fcb7b523aedd35b8ff1414bd1d554794f144474',
            '9b273ebe335540b87be899abe169389ed61ed262c3a0a16e4998bbf752f0bee3',
            '1e0070b92429c151b33bdd1bb4430a0e650a3dfc94d404054e93c8568330ecc505',
            'e3b64149f1b76231686d592d1d4af984ce2826ba03c2224a92f95f9526130ce4eb' .
                '40',
            '5f8e378120b73db9eefa65ddcdcdcb4acd8046c31a5e47f298caa400937d5623f1' .
                '394b',
            '74c757a4165a1782c933e587353a9fd8f6d7bf26b7f51b52c542747030bfb3d560' .
                'c2e5c2',
            '2d5ee85cc238b923806dd98db18919d1924f2340ec88917d4ce1799cbfd5f2cb9d' .
                'f99db2e1',
            'c93ff727e6f9822efec0a77eed0025c0eff19127bf8746b7c71c2a098f57cef02f' .
                'ebb86a1e6c',
            'adfb6d7ba13779a5dd1bbf268e400f4156f0f5c9d5b670ff539e1d9c1a63373416' .
                'f3001f338407',
            '3a6900e58a448887d77c5911e4bdde620e64f25b2d71723fa60f7cb3efa7c320b6' .
                '153bdbc3287949',
            '413eb0fd379b32dd88e82242a87cc58ce3e64c72352387a4c70f92ee5c8d23fa7e' .
                'cd86f6df170a32d2',
            '92d0d3cacc3e25628caf6f2c4cd50d25d154ac45098f531d690230b859f37cfe08' .
                '9eb169f76bba72a3ff',
            '92f6ccc11a9a3bee520b17e0cddc4550c0e9cf47ddd9a6161284259ffb161c1d06' .
                '75b505cb1066872768e8',
            'a3cd675804e6be7f120138a9eaadcd56bb7763d1c046e87fe0d358c8276b0d2462' .
                '1f46c60b46e397933b75b4',
            '304a1af53cbdd6486b8419d1ebd5e9528c540d8dc46a10be49067f46a061722957' .
                '7015d776783f702b2954df43',
            'd8a6358970446453ac0c82c758644ab68989b5b4f06f9768807ce0c5f2a0dbac1e' .
                '8450f4e3a02deecf7b54b6a45d',
            '1264b8dee9ac4aa8de69a43ada95cc95f20230f33836d4a1db8c2466ab38361686' .
                'e5ac282025ccc2e0f6a1cd98a4dd',
            '7eed787abaa7f4e8b8aa3090f0676201cfbaaf350899661cdd5216ac0b5cd87444' .
                '3f5c0688ffd7ca1ccbfe1ca7e1a3f5',
            '8907f0218585167962a8e8213559a643dd03c2bf1a7a5ad3e3bc5f88c0ff1532ee' .
                '8cd29880e7e0e68da22a5798aef27cc5',
            '12dea17b0733e5060751b1115e10c3d4b2f4583bcd009d9f1f42ec23d4a6a0df11' .
                '85d3abbdbe86de08569e70583d6de1c1fe',
            '8ff75e91f1de547dc3a25472db2f51f5910a290c449603da54207b5e39bd735d24' .
                '0ec913b52df90709b5d29357971d6c341452',
            '4a3b16b12400f38e74778efc3a4caa52ec6fdf6b0180a5bfac9189e52e162c10e8' .
                '911a54ab33e2b389ee1949e58edaa119e2b2b9',
            'c9943e7186fdc9bbfa1d7087fa7086babe6fcf95a6196d1772187854071304e2f1' .
                'fff39e6e6f48f76addb16d5c00249e0523aac91f',
            '0297f16fdd34add9cc87b4adf816525b590ba08ac733c43f8d225d194df4f9c83b' .
                '4dce617be51e25b5f6c80dff249f27c707de20e422',
            '576bb891eab9930998e2e73b5d0498e3c5f040f8dec9397a8c7a622c17de01fee7' .
                'cc936e3bd4de1f7fd8b31dea9e70c65462bbb5dc7b50',
            '9416a57ae7c8c51c6e008f940fe06d8ebc02c350c19a2f71583a6d260b085670d7' .
                '3a95248fef0f4cae5292ba7db1189a7cd9c51122ba7913',
            'ea644b9051cca5eee8868a553e3f0f4e14739e1555474151156e10578256b288a2' .
                '33870dd43a380765400ea446df7f452c1e03a9e5b6731256',
            'f99cc1603de221abc1ecb1a7eb4bbf06e99561d1cc5541d8d601bae2b1dd3cbe44' .
                '8ac276667f26de5e269183a09f7deaf35d33174b3cc8ad4aa2',
            'ee2be1ec57fdac23f89402a534177eca0f4b982a4ed2c2e900b6a79e1f47a2d023' .
                'eff2e647baf4f4c0da3a28d08a44bc780516974074e2523e6651',
            '9cda001868949a2bad96c5b3950a8315e6e5214d0b54dcd596280565d351806ef2' .
                '2cf3053f63623da72fcad9afa3896641658632334c9ec4f644c984',
            'c6d6722a916651a8671383d8260873347d9c248696b4cb3dac4dea9ba57ed97112' .
                '7cb18e44211d7e14177ace248b3c6e0785356ee261ebdc6ef0faf143',
            '5dd258a3e7505bc6b9776b0df25676a1c19e2c8258c7b5f2e361423523d96299eb' .
                '6827bc7c27e7bca2d2b59d717c2ebcb05e6dcaa32289d96fae9a4077ef',
            '19c14de35fe19c92cc0e624280e4136355d4cfa9a0a98b090c4b06f56650219207' .
                '25852ff1f566b0c8c37157b25fb9f947a2e70b40577a17860a0732c170ac',
            '5fcdcc02be7714a0dbc77df498bf999ea9225d564adca1c121c9af03af92cac817' .
                '7b9b4a86bcc47c79aa32aac58a3fef967b2132e9352d4613fe890beed2571b'
        );
        $salt = '5b6b41ed9b343fe0';
        $personal = '5126fb2a37400d2a';

        $key = '';
        for ($h = 0; $h < 64; ++$h) {
            $key .= ParagonIE_Sodium_Core_Util::intToChr($h);
        }

        $in = '';
        for ($i = 0; $i < 64; ++$i) {
            $in .= ParagonIE_Sodium_Core_Util::intToChr($i);
            $state = ParagonIE_Sodium_Compat::crypto_generichash_init_salt_personal(
                ParagonIE_Sodium_Core_Util::substr((string) $key, 0, $i + 1),
                $i + 1,
                $salt,
                $personal
            );
            if ($i === 1) {
                $exp0 = '0acbbdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5e4e0d0cf4b636b35260e0d1fbf0e60ab5e8c73cdcdbbb17e4a164a2329a9d23a0000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000';
                $this->assertSame($exp0, bin2hex($state), 'state before update');
            }
            ParagonIE_Sodium_Compat::crypto_generichash_update($state, ParagonIE_Sodium_Core_Util::substr($in, 0, $i));
            if ($i === 1) {
                $exp1 = '0acbbdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5e4e0d0cf4b636b35260e0d1fbf0e60ab5e8c73cdcdbbb17e4a164a2329a9d23a0000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008100000000000000000000000000000000000000000000000000000000000000';
                $this->assertSame($exp1, bin2hex($state), 'state after update');
            }
            $out = ParagonIE_Sodium_Compat::crypto_generichash_final($state, $i + 1);
            $this->assertEquals(
                $outputs[$i],
                ParagonIE_Sodium_Core_Util::bin2hex($out),
                'BLAKE2b Personal (i = ' . $i . ' failed)'
            );
        }
    }

    /**
     * @covers ParagonIE_Sodium_Core_BLAKE2b::update()
     * @throws SodiumException
     * @throws TypeError
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

    /**
     * @covers ParagonIE_Sodium_Core_BLAKE2b::increment_counter()
     */
    public function testCounter()
    {
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

        for ($i = 0; $i < 4; ++$i) {
            ParagonIE_Sodium_Core_BLAKE2b::increment_counter($ctx, 1 << 30);
        }
        $this->assertEquals(1026, $ctx[1][0][1]);
        $this->assertEquals(1, $ctx[1][0][0]);
    }

    /**
     * Make sure our 'context' string is consistent.
     *
     * @covers ParagonIE_Sodium_Core_BLAKE2b::init()
     * @covers ParagonIE_Sodium_Core_BLAKE2b::update()
     * @covers ParagonIE_Sodium_Core_BLAKE2b::contextToString()
     * @covers ParagonIE_Sodium_Core_BLAKE2b::stringToSplFixedArray()
     */
    public function testContext()
    {
        $ctxA = ParagonIE_Sodium_Compat::crypto_generichash_init();

        if (PHP_INT_SIZE === 4) {
            $ctxB = ParagonIE_Sodium_Core32_BLAKE2b::init(null, 32);
        } else {
            $ctxB = ParagonIE_Sodium_Core_BLAKE2b::init(null, 32);
        }

        $chunks = array(
            'Paragon Initiative ',
            'Enterprises, LLC',
            str_repeat("\x7e", 128),
            str_repeat("\x4d", 256),
            str_repeat("\x2f", 128),
            str_repeat("\x2e", 128),
            str_repeat("0", 128),
            str_repeat("\x4e", 64),
            str_repeat("\x4f", 257),
            str_repeat("\x0a", 511)
        );
        foreach ($chunks as $i => $chk) {
            ParagonIE_Sodium_Compat::crypto_generichash_update($ctxA, $chk);
            if (PHP_INT_SIZE === 4) {
                $chunk = ParagonIE_Sodium_Core32_BLAKE2b::stringToSplFixedArray($chk);
                ParagonIE_Sodium_Core32_BLAKE2b::update(
                    $ctxB,
                    $chunk,
                    $chunk->count()
                );
            } else {
                $chunk = ParagonIE_Sodium_Core_BLAKE2b::stringToSplFixedArray($chk);
                ParagonIE_Sodium_Core_BLAKE2b::update(
                    $ctxB,
                    $chunk,
                    $chunk->count()
                );
            }
            /** @var string $ctxStrB */
            if (PHP_INT_SIZE === 4) {
                $ctxStrB = ParagonIE_Sodium_Core32_BLAKE2b::contextToString($ctxB);
            } else {
                $ctxStrB = ParagonIE_Sodium_Core_BLAKE2b::contextToString($ctxB);
            }

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
     * @covers ParagonIE_Sodium_Core_BLAKE2b::init()
     * @covers ParagonIE_Sodium_Core_BLAKE2b::update()
     * @covers ParagonIE_Sodium_Core_BLAKE2b::finish()
     *
     * @throws SodiumException
     * @throws Exception
     */
    public function testGenericHashStream()
    {
        $ctx = ParagonIE_Sodium_Compat::crypto_generichash_init();
        $this->assertSame(
            '28c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
            bin2hex($ctx),
            'Context initialization is incorrect.'
        );
        ParagonIE_Sodium_Compat::crypto_generichash_update($ctx, 'Paragon Initiative ');
        ParagonIE_Sodium_Compat::crypto_generichash_update($ctx, 'Enterprises, LLC');
        $this->assertSame(
            'df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8',
            bin2hex(ParagonIE_Sodium_Compat::crypto_generichash_final($ctx)),
            'Chosen input.'
        );

        for ($i = 1; $i < 9; ++$i) {
            $data = random_bytes(1 << $i);
            $data2 = random_bytes(1 << $i);

            // Hash 1
            $hash = ParagonIE_Sodium_Compat::crypto_generichash($data . $data2);

            // Hash 2
            $ctx = ParagonIE_Sodium_Compat::crypto_generichash_init(null, 32);
            ParagonIE_Sodium_Compat::crypto_generichash_update($ctx, $data);
            ParagonIE_Sodium_Compat::crypto_generichash_update($ctx, $data2);
            $hash2 = ParagonIE_Sodium_Compat::crypto_generichash_final($ctx);

            // Hash 3
            $out = new SplFixedArray(32);
            if (PHP_INT_SIZE === 4) {
                $d1s = ParagonIE_Sodium_Core32_BLAKE2b::stringToSplFixedArray($data);
                $d2s = ParagonIE_Sodium_Core32_BLAKE2b::stringToSplFixedArray($data2);
                $ctx = ParagonIE_Sodium_Core32_BLAKE2b::init(null, 32);
                ParagonIE_Sodium_Core32_BLAKE2b::update($ctx, $d1s, $d1s->count());
                ParagonIE_Sodium_Core32_BLAKE2b::update($ctx, $d2s, $d2s->count());
                ParagonIE_Sodium_Core32_BLAKE2b::finish($ctx, $out);
                $hash3 = ParagonIE_Sodium_Core32_BLAKE2b::SplFixedArrayToString($out);
            } else {
                $d1s = ParagonIE_Sodium_Core_BLAKE2b::stringToSplFixedArray($data);
                $d2s = ParagonIE_Sodium_Core_BLAKE2b::stringToSplFixedArray($data2);
                $ctx = ParagonIE_Sodium_Core_BLAKE2b::init(null, 32);
                ParagonIE_Sodium_Core_BLAKE2b::update($ctx, $d1s, $d1s->count());
                ParagonIE_Sodium_Core_BLAKE2b::update($ctx, $d2s, $d2s->count());
                ParagonIE_Sodium_Core_BLAKE2b::finish($ctx, $out);
                $hash3 = ParagonIE_Sodium_Core_BLAKE2b::SplFixedArrayToString($out);
            }

            $this->assertSame(bin2hex($hash), bin2hex($hash3), 'Generichash streaming is failing (' . $i . ') a');
            $this->assertSame(bin2hex($hash2), bin2hex($hash3), 'Generichash streaming is failing (' . $i . ') b');
            $this->assertSame(bin2hex($hash2), bin2hex($hash), 'Generichash streaming is failing (' . $i . ') c');
        }

        $data = random_bytes(1 << $i);
        $data2 = random_bytes(1 << $i);
        $k = random_bytes(32);

        // Hash 1
        $hash = ParagonIE_Sodium_Compat::crypto_generichash($data . $data2, $k);

        // Hash 2
        $ctx = ParagonIE_Sodium_Compat::crypto_generichash_init($k, 32);
        ParagonIE_Sodium_Compat::crypto_generichash_update($ctx, $data);
        ParagonIE_Sodium_Compat::crypto_generichash_update($ctx, $data2);
        $hash2 = ParagonIE_Sodium_Compat::crypto_generichash_final($ctx);

        // Hash 3
        $out = new SplFixedArray(32);
        if (PHP_INT_SIZE === 4) {
            $d1s = ParagonIE_Sodium_Core32_BLAKE2b::stringToSplFixedArray($data);
            $d2s = ParagonIE_Sodium_Core32_BLAKE2b::stringToSplFixedArray($data2);
            $key = ParagonIE_Sodium_Core32_BLAKE2b::stringToSplFixedArray($k);
            $ctx = ParagonIE_Sodium_Core32_BLAKE2b::init($key, 32);
            ParagonIE_Sodium_Core32_BLAKE2b::update($ctx, $d1s, $d1s->count());
            ParagonIE_Sodium_Core32_BLAKE2b::update($ctx, $d2s, $d2s->count());
            ParagonIE_Sodium_Core32_BLAKE2b::finish($ctx, $out);
            $hash3 = ParagonIE_Sodium_Core32_BLAKE2b::SplFixedArrayToString($out);
        } else {
            $d1s = ParagonIE_Sodium_Core_BLAKE2b::stringToSplFixedArray($data);
            $d2s = ParagonIE_Sodium_Core_BLAKE2b::stringToSplFixedArray($data2);
            $key = ParagonIE_Sodium_Core_BLAKE2b::stringToSplFixedArray($k);
            $ctx = ParagonIE_Sodium_Core_BLAKE2b::init($key, 32);
            ParagonIE_Sodium_Core_BLAKE2b::update($ctx, $d1s, $d1s->count());
            ParagonIE_Sodium_Core_BLAKE2b::update($ctx, $d2s, $d2s->count());
            ParagonIE_Sodium_Core_BLAKE2b::finish($ctx, $out);
            $hash3 = ParagonIE_Sodium_Core_BLAKE2b::SplFixedArrayToString($out);
        }

        $this->assertSame(bin2hex($hash), bin2hex($hash3), 'Generichash streaming is failing (' . $i . ') a');
        $this->assertSame(bin2hex($hash2), bin2hex($hash3), 'Generichash streaming is failing (' . $i . ') b');
        $this->assertSame(bin2hex($hash2), bin2hex($hash), 'Generichash streaming is failing (' . $i . ') c');
    }

    /**
     * @covers ParagonIE_Sodium_Core_BLAKE2b
     * @throws SodiumException
     * @throws TypeError
     */
    public function testRotate()
    {
        if (PHP_INT_SIZE === 4) {
            $int = ParagonIE_Sodium_Core32_BLAKE2b::new64(0x7f000000, 0x3ffffff0);
            $expected = ParagonIE_Sodium_Core32_BLAKE2b::new64(0x3f800000, 0x1ffffff8);
            $calc = ParagonIE_Sodium_Core32_BLAKE2b::rotr64($int, 1);
            $this->assertEquals($expected->toArray(), $calc->toArray());

            $expected = ParagonIE_Sodium_Core32_BLAKE2b::new64(0xfff07f00, 0x00003fff);
            $calc = ParagonIE_Sodium_Core32_BLAKE2b::rotr64($int, 16);
            $this->assertEquals($expected->toArray(), $calc->toArray());

            $expected = ParagonIE_Sodium_Core32_BLAKE2b::new64(0x3ffffff0, 0x7f000000);
            $calc = ParagonIE_Sodium_Core32_BLAKE2b::rotr64($int, 32);
            $this->assertEquals($expected->toArray(), $calc->toArray());
        } else {
            $int = ParagonIE_Sodium_Core_BLAKE2b::new64(0x7f000000, 0x3ffffff0);
            $expected = ParagonIE_Sodium_Core_BLAKE2b::new64(0x3f800000, 0x1ffffff8);
            $calc = ParagonIE_Sodium_Core_BLAKE2b::rotr64($int, 1);
            $this->assertEquals($expected->toArray(), $calc->toArray());

            $expected = ParagonIE_Sodium_Core_BLAKE2b::new64(0xfff07f00, 0x00003fff);
            $calc = ParagonIE_Sodium_Core_BLAKE2b::rotr64($int, 16);
            $this->assertEquals($expected->toArray(), $calc->toArray());

            $expected = ParagonIE_Sodium_Core_BLAKE2b::new64(0x3ffffff0, 0x7f000000);
            $calc = ParagonIE_Sodium_Core_BLAKE2b::rotr64($int, 32);
            $this->assertEquals($expected->toArray(), $calc->toArray());
        }
    }
}
