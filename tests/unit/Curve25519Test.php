<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\CoversClass;

/**
 * Class Curve25519Test
 */
#[CoversClass(ParagonIE_Sodium_Core_Curve25519::class)]
#[CoversClass(ParagonIE_Sodium_Core_Curve25519_Fe::class)]
class Curve25519Test extends TestCase
{
    /**
     * @before
     */
    #[Before]
    public function before(): void
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @throws TypeError
     */
    public function testFe0(): void
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
     * @throws SodiumException
     * @throws TypeError
     */
    public function testFe1(): void
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
     * @throws Exception
     * @throws TypeError
     */
    public function testFeAdd(): void
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
     * @throws TypeError
     */
    public function testFeSq(): void
    {
        $g = ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
            array(
                70051,
                -1455864,
                -220599,
                -10799067,
                717124,
                -11560168,
                671906,
                12781942,
                1056405,
                -13773822
            )
        );

        $expected = ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
            array(
                -4080589,
                -8170580,
                19250910,
                11583187,
                -9496298,
                14604333,
                21151415,
                6893025,
                -30945925,
                -5379679
            )
        );

        $h = ParagonIE_Sodium_Core_Curve25519::fe_sq($g);
        $this->assertSame(
            '20bcc1af4e0deef62d69da179645c6db2cd8de6e7d850a6f49b3d77c22687a6b',
            bin2hex(ParagonIE_Sodium_Core_Curve25519::fe_tobytes($h))
        );
        $this->assertEquals($expected, $h);
    }

    /**
     * @throws TypeError
     */
    public function testFeSqDouble(): void
    {
        $g = ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
            array(
                70051,
                -1455864,
                -220599,
                -10799067,
                717124,
                -11560168,
                671906,
                12781942,
                1056405,
                -13773822
            )
        );

        $expected = ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
            array(
                -8161178,
                -16341160,
                -28607044,
                -10388057,
                -18992595,
                -4345766,
                -24806033,
                13786051,
                5217014,
                -10759359
            )
        );

        $h = ParagonIE_Sodium_Core_Curve25519::fe_sq2($g);
        $this->assertSame(
            '5378835f9d1adced5bd2b42f2c8b8cb759b0bdddfa0a15de9266aff944d0f456',
            bin2hex(ParagonIE_Sodium_Core_Curve25519::fe_tobytes($h))
        );
        $this->assertEquals($expected, $h);
    }

    /**
     * @throws Exception
     * @throws TypeError
     */
    public function testFeSub(): void
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
     * @throws TypeError
     */
    public function testReduce(): void
    {
        $input = ParagonIE_Sodium_Core_Util::hex2bin(
            "2771062b6b536fe7ffbdda0320c3827b035df10d284df3f08222f04dbca7a4c2" .
            "0ef15bdc988a22c7207411377c33f2ac09b1e86a046234283768ee7ba03c0e9f"
        );
        $reduced = ParagonIE_Sodium_Core_Curve25519::sc_reduce($input);
        $this->assertSame(
            '86eabc8e4c96193d290504e7c600df6cf8d8256131ec2c138a3e7e162e525404',
            ParagonIE_Sodium_Core_Util::bin2hex($reduced),
            'sd_reduce is not working'
        );

        $input = ParagonIE_Sodium_Core_Util::hex2bin(
            "dc0e1b48b1f2d9d3a6638a43c986c49ecbfafba209fff7a801f9d8f776c1fc79" .
            "5dd9dd8f4c272b92210c923ba7940955136f7e68c4bee52a6562f8171785ce10"
        );
        $reduced = ParagonIE_Sodium_Core_Curve25519::sc_reduce($input);
        $this->assertSame(
            'd8e7f39643da186a4a690c8cf6a7987bc4d2fb7bede4e7cec89f8175da27730a',
            ParagonIE_Sodium_Core_Util::bin2hex($reduced),
            'sd_reduce is not working'
        );
    }

    /**
     * @throws TypeError
     */
    public function testScMulAdd(): void
    {
        $a = ParagonIE_Sodium_Core_Util::hex2bin(
            "86eabc8e4c96193d290504e7c600df6cf8d8256131ec2c138a3e7e162e525404"
        );
        $b = ParagonIE_Sodium_Core_Util::hex2bin(
            "307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f9b4f0afe280b746a778684e75442502057b7473a03f08f96f5a38e9287e01f8f"
        );
        $c = ParagonIE_Sodium_Core_Util::hex2bin(
            "f38907308c893deaf244787db4af53682249107418afc2edc58f75ac58a07404044098c2a990039cde5b6a4818df0bfb6e40dc5dee54248032962323e701352d"
        );
        $d = ParagonIE_Sodium_Core_Curve25519::sc_muladd($a, $b, $c);
        $this->assertSame(
            '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
            ParagonIE_Sodium_Core_Util::bin2hex($d),
            'sd_mulcadd is not working'
        );
    }

    /**
     * @throws SodiumException
     * @throws TypeError
     */
    public function testGeSelect(): void
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

    public function testFeMul(): void
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

        $g = ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
            array(
                70051,
                -1455864,
                -220599,
                -10799067,
                717124,
                -11560168,
                671906,
                12781942,
                1056405,
                -13773822
            )
        );
        $this->assertEquals(
            $g,
            ParagonIE_Sodium_Core_Curve25519::fe_mul($g, ParagonIE_Sodium_Core_Curve25519::fe_1())
        );

        $expected = ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
            array(
                7544649,
                10532726,
                -19637653,
                -7342246,
                3908574,
                13668567,
                19809982,
                -8668475,
                -9608131,
                -4851782
            )
        );

        $h = ParagonIE_Sodium_Core_Curve25519::fe_mul($f, $g);
        $this->assertEquals($expected, $h);


        $f = ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
            array(
                0x3ffffff,
                0x3ffffff,
                0x3ffffff,
                0x3ffffff,
                0x3ffffff,
                0x3ffffff,
                0x3ffffff,
                0x3ffffff,
                0x3ffffff,
                0x3ffffff
            )
        );
        $g = ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
            array(
                0x1ffffff,
                0x0ffffff,
                0x1ffffff,
                0x0ffffff,
                0x1ffffff,
                0x0ffffff,
                0x1ffffff,
                0x0ffffff,
                0x1ffffff,
                0x0ffffff
            )
        );
        $this->assertEquals(
            $g,
            ParagonIE_Sodium_Core_Curve25519::fe_mul($g, ParagonIE_Sodium_Core_Curve25519::fe_1())
        );

        $expected = ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
            array(
                -33554165,
                16777160,
                33554393,
                16777168,
                33554402,
                16777177,
                33554411,
                16777186,
                33554420,
                16777195
            )
        );

        $h = ParagonIE_Sodium_Core_Curve25519::fe_mul($f, $g);
        $this->assertEquals($expected, $h);
    }

    public function testGeMAdd(): void
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

    public function testGeScalarmultBase(): void
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
     * @throws SodiumException
     * @throws TypeError
     */
    public function testSlide(): void
    {
        $a = ParagonIE_Sodium_Core_Util::hex2bin(
            'fc2ef90e2ddab38c55d0edbf41167048061a03b99d00112dcc92777c1b17300c' .
            'bd84d56b93d272eb01a2ffb5557bda3922360e402c29d05cda3f0debabaf5ce5'
        );
        $this->assertEquals(
            array(
                0, 0, -1, 0, 0, 0, 0, 0, 15, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, -1,
                0, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 0, -15, 0, 0,
                0, 0, -9, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 0, -7, 0, 0, 0, 0,
                -7, 0, 0, 0, 0, 11, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, -3, 0, 0, 0,
                0, -9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0,
                0, -7, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0,
                0, 9, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0,
                0, 3, 0, 0, 0, 0, 0, 0, 0, -7, 0, 0, 0, 0, 0, -9, 0, 0, 0, 0,
                0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -15, 0, 0, 0, 0, 9, 0,
                0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, -13, 0, 0, 0, 0, 0, -13, 0,
                0, 0, 0, -3, 0, 0, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0,
                0, -9, 0, 0, 0, 0, 0, -7, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0,
                0, 0, 3, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0
            ),
            ParagonIE_Sodium_Core_Curve25519::slide($a),
            'slide()'
        );
        $b = ParagonIE_Sodium_Core_Util::hex2bin(
            '36a6d2748f6ab8f76c122a562d55343cb7c6f15c8a45bd55bd8b9e9fadd2363f' .
            '370cb78fba42c550d487b9bd7413312b6490c8b3ee2cea638997172a9c8c250f'
        );
        $this->assertEquals(
            array(
                0, -5, 0, 0, 0, 0, -7, 0, 0, 0, 0, -11, 0, 0, 0, 0, -13, 0, 0,
                0, 0, 7, 0, 0, 0, 0, -3, 0, 0, 0, 0, -1, 0, 0, 0, 0, 9, 0, 0,
                0, 0, -11, 0, 0, 0, 0, 0, -15, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0,
                0, -1, 0, 0, 0, 0, 13, 0, 0, 0, 0, -13, 0, 0, 0, 0, 5, 0, 0, 0,
                0, 0, 0, -11, 0, 0, 0, 0, -7, 0, 0, 0, 0, 11, 0, 0, 0, 0, 13,
                0, 0, 0, 0, 9, 0, 0, 0, 0, -11, 0, 0, 0, 0, 9, 0, 0, 0, 0, 3,
                0, 0, 0, 0, 0, 15, 0, 0, 0, 0, 0, -9, 0, 0, 0, 0, 0, -5, 0, 0,
                0, 0, -7, 0, 0, 0, 0, 0, -7, 0, 0, 0, 0, 0, 0, -3, 0, 0, 0, 0,
                -13, 0, 0, 0, 0, 3, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, -11, 0,
                0, 0, 0, 0, 0, 0, -9, 0, 0, 0, 0, 11, 0, 0, 0, 0, -3, 0, 0, 0,
                0, 0, 15, 0, 0, 0, 0, -15, 0, 0, 0, 0, -1, 0, 0, 0, 0, -3, 0,
                0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 0, 11, 0, 0, 0, 0, 5, 0, 0, 0,
                0, 13, 0, 0, 0, 0, -5, 0, 0, 0, 0, -3, 0, 0, 0, 0, 0, 0, 0, 1, 0
            ),
            ParagonIE_Sodium_Core_Curve25519::slide($b),
            'slide()'
        );
    }

    /**
     * @throws SodiumException
     * @throws TypeError
     */
    public function testGeDoubleScalarMultVartime(): void
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

    /**
     * @throws TypeError
     */
    public function testGeP3Double(): void
    {
        $h = new ParagonIE_Sodium_Core_Curve25519_Ge_P3(
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(-1594322, -5977244, 5464532, 10581198, -25979371, 12080549, -33350018, 1574611, 19995101, 13564973)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(-18723709, -973029, -25256245, 15814990, -1761947, -13933478, 4253868, 13520360, -19620859, 9124635)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(13325287, -281729, -20379096, -7440165, 33350335, -2779381, 3728108, -4645219, 8597785, 10781386)
            ),
            ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                array(-2132132, -9321290, -6314567, -5742359, 26868584, 6121874, -12905835, -8351796, -6684490, 2810736)
            )
        );
        $r = ParagonIE_Sodium_Core_Curve25519::ge_p3_dbl($h);
        $this->assertEquals(
            $r,
            new ParagonIE_Sodium_Core_Curve25519_Ge_P1p1(
                ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                    array(-35283196, -12206287, -25587079, -781847, -12122107, -28300439, 17653143, -6739204, 53430184, -2709074)
                ),
                ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                    array(41346847, -651104, 44099729, -11567738, 24203910, 15902281, -7669229, -5701807, -36827255, -8892117)
                ),
                ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                    array(-8486765, -30734394, -22721233, -6397156, 15030434, -12155039, 45632571, 6384575, -16815183, 4041753)
                ),
                ParagonIE_Sodium_Core_Curve25519_Fe::fromArray(
                    array(20359676, 27238564, 53876343, -3630392, 747030, 27670722, -30548977, -5701679, 9121398, -14580561)
                )
            )
        );
    }

    /**
     * @throws SodiumException
     * @throws TypeError
     */
    public function testGeP3ToBytes32(): void
    {
        $R = new ParagonIE_Sodium_Core_Curve25519_Ge_P3(
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
        $bytes = ParagonIE_Sodium_Core_Curve25519::ge_p3_tobytes($R);
        $this->assertSame(
            '36a6d2748f6ab8f76c122a562d55343cb7c6f15c8a45bd55bd8b9e9fadd2363f',
            bin2hex($bytes),
            'Check ge_p3_tobytes for correctness'
        );
    }

    /**
     * @throws TypeError
     */
    public function testFromBytes(): void
    {
        $a = ParagonIE_Sodium_Core_Curve25519::fe_frombytes(
            ParagonIE_Sodium_Core_Util::hex2bin('f7efaafeb83be2f97cd351b48e78f9d158269cdecedbcb503913172158b69336')
        );
        $this->assertSame('f7efaafe', bin2hex(ParagonIE_Sodium_Core_Util::store32_le($a[0])));
        $this->assertSame('40ee8e00', bin2hex(ParagonIE_Sodium_Core_Util::store32_le($a[1])));
        $this->assertSame('3c9f6ffe', bin2hex(ParagonIE_Sodium_Core_Util::store32_le($a[2])));
        $this->assertSame('8fa27500', bin2hex(ParagonIE_Sodium_Core_Util::store32_le($a[3])));
        $this->assertSame('e2e547ff', bin2hex(ParagonIE_Sodium_Core_Util::store32_le($a[4])));
        $this->assertSame('59269c00', bin2hex(ParagonIE_Sodium_Core_Util::store32_le($a[5])));
        $this->assertSame('6fe7ed01', bin2hex(ParagonIE_Sodium_Core_Util::store32_le($a[6])));
        $this->assertSame('192a6700', bin2hex(ParagonIE_Sodium_Core_Util::store32_le($a[7])));
        $this->assertSame('71118201', bin2hex(ParagonIE_Sodium_Core_Util::store32_le($a[8])));
        $this->assertSame('d94eda00', bin2hex(ParagonIE_Sodium_Core_Util::store32_le($a[9])));
    }

    public function test121666Mul(): void
    {
        $f = array(
            6334098, -296341, -25402037, 14130508, 28301433, 10881396, -32579582, 21932206, 23531802, -8703561
        );
        $g = array(
            32682354, 16401777, 279075, 7462323, 33495638, 5862485, 24776867, -12488670, 21945689, -16644908
        );
        $fe_f = ParagonIE_Sodium_Core_Curve25519_Fe::fromArray($f);
        $fe_g = ParagonIE_Sodium_Core_Curve25519_Fe::fromArray($g);
        $mult = ParagonIE_Sodium_Core_X25519::fe_mul121666($fe_f);
        for ($i = 0; $i < 10; ++$i) {
            $this->assertEquals($fe_g[$i], $mult[$i]);
        }
    }
}
