<?php

class Curve25519Test extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @covers ParagonIE_Sodium_Core_Curve25519::fe_0()
     */
    public function testFe0()
    {
        $f = array(
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        );
        $fe_f = ParagonIE_Sodium_Core_Curve25519_Fe::fromArray($f);
        $r = ParagonIE_Sodium_Core_Curve25519::fe_0();
        for ($i = 0; $i < 10; ++$i) {
            $this->assertEquals($r[$i], $fe_f[$i]);
        }
    }

    /**
     * @covers ParagonIE_Sodium_Core_Curve25519::fe_1()
     */
    public function testFe1()
    {
        $f = array(
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        );
        $fe_f = ParagonIE_Sodium_Core_Curve25519_Fe::fromArray($f);
        $r = ParagonIE_Sodium_Core_Curve25519::fe_1();
        for ($i = 0; $i < 10; ++$i) {
            $this->assertEquals($r[$i], $fe_f[$i]);
        }
    }

    /**
     * @covers ParagonIE_Sodium_Core_Curve25519::fe_add()
     */
    public function testFeAdd()
    {
        $f = array(
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535)
        );
        $g = array(
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535)
        );
        $h = array();
        for ($i = 0; $i < 10; ++$i) {
            $h[$i] = $f[$i] + $g[$i];
        }

        $fe_f = ParagonIE_Sodium_Core_Curve25519_Fe::fromArray($f);
        $fe_g = ParagonIE_Sodium_Core_Curve25519_Fe::fromArray($g);
        $fe_h = ParagonIE_Sodium_Core_Curve25519_Fe::fromArray($h);
        $r = ParagonIE_Sodium_Core_Curve25519::fe_add($fe_f, $fe_g);

        for ($i = 0; $i < 10; ++$i) {
            $this->assertEquals($r[$i], $fe_h[$i]);
        }
        $this->assertEquals($r, $fe_h, 'Addition error!');
    }

    /**
     * @covers ParagonIE_Sodium_Core_Curve25519::fe_sub()
     */
    public function testFeSub()
    {
        $f = array(
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535)
        );
        $g = array(
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535),
            random_int(0, 65535)
        );
        $h = array();
        for ($i = 0; $i < 10; ++$i) {
            $h[$i] = $f[$i] - $g[$i];
        }

        $fe_f = ParagonIE_Sodium_Core_Curve25519_Fe::fromArray($f);
        $fe_g = ParagonIE_Sodium_Core_Curve25519_Fe::fromArray($g);
        $fe_h = ParagonIE_Sodium_Core_Curve25519_Fe::fromArray($h);
        $r = ParagonIE_Sodium_Core_Curve25519::fe_sub($fe_f, $fe_g);

        for ($i = 0; $i < 10; ++$i) {
            $this->assertEquals($r[$i], $fe_h[$i]);
        }
        $this->assertEquals($r, $fe_h, 'Subtraction error!');
    }

    /**
     * @covers ParagonIE_Sodium_Core_Curve25519::sc_reduce()
     */
    public function testReduce()
    {
        $input = ParagonIE_Sodium_Core_Util::hex2bin(
            "dc0e1b48b1f2d9d3a6638a43c986c49ecbfafba209fff7a801f9d8f776c1fc79" .
            "5dd9dd8f4c272b92210c923ba7940955136f7e68c4bee52a6562f8171785ce10"
        );
        $reduced = ParagonIE_Sodium_Core_Curve25519::sc_reduce($input);
        $this->assertSame(
            'd8e7f39643da186a4a690c8cf6a7987bc4d2fb7bede4e7cec89f8175da27730a',
            bin2hex($reduced),
            'sd_reduce is not working'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Core_Curve25519::ge_select()
     */
    public function testGeSelect()
    {
        $this->assertEquals(
            ParagonIE_Sodium_Core_Curve25519::ge_select(0, 6),
            new ParagonIE_Sodium_Core_Curve25519_Ge_Precomp(
                ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                    array(-15371964, -12862754, 32573250, 4720197, -26436522, 5875511, -19188627, -15224819, -9818940, -12085777)
                ),
                ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                    array(-8549212, 109983, 15149363, 2178705, 22900618, 4543417, 3044240, -15689887, 1762328, 14866737)
                ),
                ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                    array(-18199695, -15951423, -10473290, 1707278, -17185920, 3916101, -28236412, 3959421, 27914454, 4383652)
                )
            ),
            'ge_select is not working.'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Core_Curve25519::fe_mul()
     */
    public function testFeMul()
    {
        $f = ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
            array(
                26853523,
                -15767542,
                10850706,
                -434120,
                -20393796,
                -13094191,
                -4793868,
                1643574,
                11273642,
                14083967
            )
        );

        $g = ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
            array(
                -10913610,
                13857413,
                -15372611,
                6949391,
                114729,
                -8787816,
                -6275908,
                -3247719,
                -18696448,
                -12055116
            )
        );

        $expected = ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
            array(
                -25012118,
                15881590,
                -29167576,
                -8241728,
                -26366797,
                6116011,
                -16287663,
                -1425685,
                -9694368,
                -16104023
            )
        );

        $h = ParagonIE_Sodium_Core_Curve25519::fe_mul($f, $g);
        $this->assertEquals($expected, $h);

        $this->assertEquals(
            $expected,
            ParagonIE_Sodium_Core_Curve25519::fe_mul($h, ParagonIE_Sodium_Core_Curve25519::fe_1())
        );

        $this->assertEquals(
            $expected,
            ParagonIE_Sodium_Core_Curve25519::fe_mul(ParagonIE_Sodium_Core_Curve25519::fe_1(), $h)
        );
        $z = ParagonIE_Sodium_Core_Curve25519::fe_0();
        $this->assertEquals(
            $z,
            ParagonIE_Sodium_Core_Curve25519::fe_mul($z, $h)
        );
    }

    /**
     * @covers ParagonIE_Sodium_Core_Curve25519::ge_madd()
     */
    public function testGeMAdd()
    {
        $p = new ParagonIE_Sodium_Core_Curve25519_Ge_P3(
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(0,0,0,0,0,0,0,0,0,0)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(1,0,0,0,0,0,0,0,0,0)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(1,0,0,0,0,0,0,0,0,0)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(0,0,0,0,0,0,0,0,0,0)
            )
        );

        $q = new ParagonIE_Sodium_Core_Curve25519_Ge_Precomp(
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(-8549212, 109983, 15149363, 2178705, 22900618, 4543417, 3044240, -15689887, 1762328, 14866737)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(-15371964, -12862754, 32573250, 4720197, -26436522, 5875511, -19188627, -15224819, -9818940, -12085777)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(18199695, 15951423, 10473290, -1707278, 17185920, -3916101, 28236412, -3959421, -27914454, -4383652)
            )
        );

        $expected = new ParagonIE_Sodium_Core_Curve25519_Ge_P1p1(
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(6822752, 12972737, -17423887, -2541492, 49337140, -1332094, 22232867, -465068, 11581268, 26952514)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(-23921176, -12752771, 47722613, 6898902, -3535904, 10418928, -16144387, -30914706, -8056612, 2780960)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(2,0,0,0,0,0,0,0,0,0)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(2,0,0,0,0,0,0,0,0,0)
            )
        );

        $r = new ParagonIE_Sodium_Core_Curve25519_Ge_P1p1();
        $this->assertEquals(
            $expected,
            ParagonIE_Sodium_Core_Curve25519::ge_madd($r, $p, $q),
            'ge_madd is still broken'
        );

        // $this->assertSame(true, true); return;
        $h = new ParagonIE_Sodium_Core_Curve25519_Ge_P3(
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(0,0,0,0,0,0,0,0,0,0)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(1,0,0,0,0,0,0,0,0,0)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(1,0,0,0,0,0,0,0,0,0)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(0,0,0,0,0,0,0,0,0,0)
            )
        );

        $t = new ParagonIE_Sodium_Core_Curve25519_Ge_Precomp(
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(23599295, -8306047, -11193664, -7687416, 13236774, 10506355, 7464579, 9656445, 13059162, 103743971)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(-17036878, 13921892, 10945806, -6033431, 27105052, -16084379, -28926210, 15006023, 3284568, -6276540)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(-7798556, -16710257, -3033922, -2874086, -28997861, -2835604, -32406664, 3839045, 641708, 101325)
            )
        );

        $expected = new ParagonIE_Sodium_Core_Curve25519_Ge_P1p1(
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(40636230, -22227939, -22139470, -1653985, -13868278, 26590734, 36390789, -5349578, 9774594, 9357215)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(6562474, 5615845, -247858, -13720847, 40341826, -5578024, -21461631, 24662468, 16343730, -3195865)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(2,0,0,0,0,0,0,0,0,0)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(2,0,0,0,0,0,0,0,0,0)
            )
        );

        $r = new ParagonIE_Sodium_Core_Curve25519_Ge_P1p1();
        $this->assertEquals(
            $expected,
            ParagonIE_Sodium_Core_Curve25519::ge_madd($r, $h, $t),
            'ge_madd is not working'
        );

        $h = new ParagonIE_Sodium_Core_Curve25519_Ge_P3(
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(0,0,0,0,0,0,0,0,0,0)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(1,0,0,0,0,0,0,0,0,0)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(1,0,0,0,0,0,0,0,0,0)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(0,0,0,0,0,0,0,0,0,0)
            )
        );

        $t = new ParagonIE_Sodium_Core_Curve25519_Ge_Precomp(
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(-12815894, -12976347, -21581243, 11784320, -25355658, -2750717, -11717903, -3814571, -358445, -10211303)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(-21703237, 6903825, 27185491, 6451973, -29577724, -9554005, -15616551, 11189268, -26829678, -53190817)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(26966642, 11152617, 32442495, 15396054, 14353839, -12752335, -3128826, -9541118, -15472047, -4166697)
            )
        );

        $expected = new ParagonIE_Sodium_Core_Curve25519_Ge_P1p1(
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(8887381, -19880172, -48766734, 5332347, 4222066, 6803288, 3898648, -15003839, 26471233, -24129350)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(-34519169, -6072522, 5604248, 18236293, -54933382, -12304722, -27334454, 7374697, -27188123, 3706744)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(2,0,0,0,0,0,0,0,0,0)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(2,0,0,0,0,0,0,0,0,0)
            )
        );
        $r = new ParagonIE_Sodium_Core_Curve25519_Ge_P1p1();
        $this->assertEquals(
            $expected,
            ParagonIE_Sodium_Core_Curve25519::ge_madd($r, $h, $t),
            'ge_madd is not working'
        );
    }

    
    public function testGeScalarmultBase()
    {
        $nonce = ParagonIE_Sodium_Core_Util::hex2bin(
            'a5cdb7382d5282472312e739b7b8fded4b0bc73a8d3b7ac24e6ee259df74800a' .
            'c19b35ef3130ed0474e0f0cc4d9ee277788775036b7025aed15c3beb29ff4eab'
        );
        $R = ParagonIE_Sodium_Core_Curve25519::ge_scalarmult_base($nonce);
        $expected = new ParagonIE_Sodium_Core_Curve25519_Ge_P3(
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(array(
                -23932472,
                11221871,
                27518927,
                -12970994,
                14275856,
                4619861,
                -14347453,
                6713345,
                -33117680,
                -10663750
            )),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(array(
                14689788,
                -10448958,
                -30321432,
                -9014186,
                14446585,
                -7985136,
                27805771,
                -13751241,
                -1536736,
                -13958946
            )),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(array(
                19689758,
                -6173146,
                -15886452,
                5649798,
                -24861313,
                -12384199,
                -2662028,
                16072970,
                5918454,
                14582476
            )),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(array(
                -9719484,
                -15496290,
                -31004425,
                -7546822,
                12427063,
                11453174,
                -8594732,
                -14149517,
                27692259,
                -14101917
            ))
        );
        $this->assertEquals(
            $expected,
            $R,
            'Check ge_scalarmult_base for correctness'
        );

        $bytes = ParagonIE_Sodium_Core_Curve25519::ge_p3_tobytes($R);
        $this->assertSame(
            '36a6d2748f6ab8f76c122a562d55343cb7c6f15c8a45bd55bd8b9e9fadd2363f',
            bin2hex($bytes),
            'Check ge_p3_tobytes for correctness'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Core_Curve25519::ge_double_scalarmult_vartime()
     */
    public function testGeDoubleScalarMultVartime()
    {
        $h = ParagonIE_Sodium_Core_Util::hex2bin(
            'fc2ef90e2ddab38c55d0edbf41167048061a03b99d00112dcc92777c1b17300c' .
            'bd84d56b93d272eb01a2ffb5557bda3922360e402c29d05cda3f0debabaf5ce5'
        );
        $A = new ParagonIE_Sodium_Core_Curve25519_Ge_P3(
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(array(
                25569346,
                24607350,
                21422669,
                3164952,
                51116803,
                27944728,
                23859688,
                12129629,
                33577468,
                23235570
            )),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(array(
                16253166, 2599808, 30616947, -12747262, 372730, 8894334, 9139202, -197177, -24298945, 15942855
            )),
            ParagonIE_Sodium_Core_Curve25519::fe_1(),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(array(
                -28155508, 13944970, 2511703, 16462880, 15250894, -7952383, -19629302, 16022930, 1783986, 16320964
            ))
        );
        $sig = ParagonIE_Sodium_Core_Util::hex2bin(
            '36a6d2748f6ab8f76c122a562d55343cb7c6f15c8a45bd55bd8b9e9fadd2363f' .
            '370cb78fba42c550d487b9bd7413312b6490c8b3ee2cea638997172a9c8c250f'
        );
        $expected = new ParagonIE_Sodium_Core_Curve25519_Ge_P2(
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(array(
                -18667682,
                9847093,
                7256576,
                -7033042,
                32767777,
                -10224836,
                25608854,
                6989354,
                -19138147,
                -13642525
            )),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(array(
                6317192,
                4477233,
                24373531,
                14977415,
                -10754696,
                -12573560,
                -20847592,
                8319048,
                13730645,
                -7760907
            )),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(array(
                32680048,
                -15342934,
                3837898,
                8050201,
                15422085,
                14178962,
                -6403825,
                -627297,
                24243949,
                12818173
            ))
        );

        $this->assertEquals(
            $expected,
            ParagonIE_Sodium_Core_Curve25519::ge_double_scalarmult_vartime($h, $A, $sig),
            'ge_double_scalarmult_vartime()'
        );
    }
}
