<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\CoversClass;

/**
 * Class Ristretto255Test
 * @package unit
 */
#[CoversClass(ParagonIE_Sodium_Core_Ristretto255::class)]
class Ristretto255Test extends TestCase
{
    /**
     * @before
     */
    #[Before]
    public function before(): void
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    public function testBadEncodings(): void
    {
        $badHex = array(

            /* Non-canonical field encodings */
            "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "0100000000000000000000000000000000000000000000000000000000000080",

            /* Negative field elements */
            "0100000000000000000000000000000000000000000000000000000000000000",
            "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "ed57ffd8c914fb201471d1c3d245ce3c746fcbe63a3679d51b6a516ebebe0e20",
            "c34c4e1826e5d403b78e246e88aa051c36ccf0aafebffe137d148a2bf9104562",
            "c940e5a4404157cfb1628b108db051a8d439e1a421394ec4ebccb9ec92a8ac78",
            "47cfc5497c53dc8e61c91d17fd626ffb1c49e2bca94eed052281b510b1117a24",
            "f1c6165d33367351b0da8f6e4511010c68174a03b6581212c71c0e1d026c3c72",
            "87260f7a2f12495118360f02c26a470f450dadf34a413d21042b43b9d93e1309",

            /* Non-square x^2 */
            "26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371",
            "4eac077a713c57b4f4397629a4145982c661f48044dd3f96427d40b147d9742f",
            "de6a7b00deadc788eb6b6c8d20c0ae96c2f2019078fa604fee5b87d6e989ad7b",
            "bcab477be20861e01e4a0e295284146a510150d9817763caf1a6f4b422d67042",
            "2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08",
            "f4a9e534fc0d216c44b218fa0c42d99635a0127ee2e53c712f70609649fdff22",
            "8268436f8c4126196cf64b3c7ddbda90746a378625f9813dd9b8457077256731",
            "2810e5cbc2cc4d4eece54f61c6f69758e289aa7ab440b3cbeaa21995c2f4232b",

            /* Negative xy value */
            "3eb858e78f5a7254d8c9731174a94f76755fd3941c0ac93735c07ba14579630e",
            "a45fdc55c76448c049a1ab33f17023edfb2be3581e9c7aade8a6125215e04220",
            "d483fe813c6ba647ebbfd3ec41adca1c6130c2beeee9d9bf065c8d151c5f396e",
            "8a2e1d30050198c65a54483123960ccc38aef6848e1ec8f5f780e8523769ba32",
            "32888462f8b486c68ad7dd9610be5192bbeaf3b443951ac1a8118419d9fa097b",
            "227142501b9d4355ccba290404bde41575b037693cef1f438c47f8fbf35d1165",
            "5c37cc491da847cfeb9281d407efc41e15144c876e0170b499a96a22ed31e01e",
            "445425117cb8c90edcbc7c1cc0e74f747f2c1efa5630a967c64f287792a48a4b",

            /* s = -1, which causes y = 0 */
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
        );
        for ($i = 0; $i < count($badHex); ++$i) {
            $s = ParagonIE_Sodium_Core_Util::hex2bin($badHex[$i]);
            $this->assertFalse(
                ParagonIE_Sodium_Compat::ristretto255_is_valid_point($s),
                "[{$badHex[$i]}] was not rejected"
            );
        }
    }

    public function testFromHash(): void
    {
        $inputHashes = array(
            "5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c1" .
            "4d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6",

            "f116b34b8f17ceb56e8732a60d913dd10cce47a6d53bee9204be8b44f6678b27" .
            "0102a56902e2488c46120e9276cfe54638286b9e4b3cdb470b542d46c2068d38",

            "8422e1bbdaab52938b81fd602effb6f89110e1e57208ad12d9ad767e2e25510c" .
            "27140775f9337088b982d83d7fcf0b2fa1edffe51952cbe7365e95c86eaf325c",

            "ac22415129b61427bf464e17baee8db65940c233b98afce8d17c57beeb7876c2" .
            "150d15af1cb1fb824bbd14955f2b57d08d388aab431a391cfc33d5bafb5dbbaf",

            "165d697a1ef3d5cf3c38565beefcf88c0f282b8e7dbd28544c483432f1cec767" .
            "5debea8ebb4e5fe7d6f6e5db15f15587ac4d4d4a1de7191e0c1ca6664abcc413",

            "a836e6c9a9ca9f1e8d486273ad56a78c70cf18f0ce10abb1c7172ddd605d7fd2" .
            "979854f47ae1ccf204a33102095b4200e5befc0465accc263175485f0e17ea5c",

            "2cdc11eaeb95daf01189417cdddbf95952993aa9cb9c640eb5058d09702c7462" .
            "2c9965a697a3b345ec24ee56335b556e677b30e6f90ac77d781064f866a3c982"
        );
        $outputHashes = array(
            '3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46',
            'f26e5b6f7d362d2d2a94c5d0e7602cb4773c95a2e5c31a64f133189fa76ed61b',
            '006ccd2a9e6867e6a2c5cea83d3302cc9de128dd2a9a57dd8ee7b9d7ffe02826',
            'f8f0c87cf237953c5890aec3998169005dae3eca1fbb04548c635953c817f92a',
            'ae81e7dedf20a497e10c304a765c1767a42d6e06029758d2d7e8ef7cc4c41179',
            'e2705652ff9f5e44d3e841bf1c251cf7dddb77d140870d1ab2ed64f1a9ce8628',
            '80bd07262511cdde4863f8a7434cef696750681cb9510eea557088f76d9e5065',
        );
        for ($i = 0; $i < count($inputHashes); ++$i) {
            $s = ParagonIE_Sodium_Compat::bin2hex(
                ParagonIE_Sodium_Compat::ristretto255_from_hash(
                    ParagonIE_Sodium_Compat::hex2bin($inputHashes[$i])
                )
            );
            $this->assertSame($outputHashes[$i], $s, 'Hash differs at index ' . $i);
        }
    }

    /**
     * @throws SodiumException
     */
    public function testScalarMult(): void
    {
        $expected = array(
            '0000000000000000000000000000000000000000000000000000000000000000',
            'e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76',
            '6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919',
            '94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259',
            'da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57',
            'e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e',
            'f64746d3c92b13050ed8d80236a7f0007c3b3f962f5ba793d19a601ebb1df403',
            '44f53520926ec81fbd5a387845beb7df85a96a24ece18738bdcfa6a7822a176d',
            '903293d8f2287ebe10e2374dc1a53e0bc887e592699f02d077d5263cdd55601c',
            '02622ace8f7303a31cafc63f8fc48fdc16e1c8c8d234b2f0d6685282a9076031',
            '20706fd788b2720a1ed2a5dad4952b01f413bcf0e7564de8cdc816689e2db95f',
            'bce83f8ba5dd2fa572864c24ba1810f9522bc6004afe95877ac73241cafdab42',
            'e4549ee16b9aa03099ca208c67adafcafa4c3f3e4e5303de6026e3ca8ff84460',
            'aa52e000df2e16f55fb1032fc33bc42742dad6bd5a8fc0be0167436c5948501f',
            '46376b80f409b29dc2b5f6f0c52591990896e5716f41477cd30085ab7f10301e',
            'e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e'
        );

        $b = ParagonIE_Sodium_Compat::hex2bin('e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76');
        $n = str_repeat("\0", ParagonIE_Sodium_Core_Ristretto255::SCALAR_BYTES);
        for ($i = 0; $i < 16; ++$i) {
            try {
                $p = ParagonIE_Sodium_Compat::scalarmult_ristretto255_base($n);
                $p2 = ParagonIE_Sodium_Compat::scalarmult_ristretto255($n, $b);
            } catch (SodiumException $ex) {
                if ($i === 0) {
                    $p = str_repeat("\0", 32);
                    $p2 = str_repeat("\0", 32);
                } else {
                    throw $ex;
                }
            }
            $this->assertSame(
                ParagonIE_Sodium_Compat::bin2hex($p),
                ParagonIE_Sodium_Compat::bin2hex($p2),
                "n = " . bin2hex($n) . ", i = {$i}"
            );
            $this->assertSame($expected[$i], ParagonIE_Sodium_Compat::bin2hex($p2), 'i = ' . $i);
            ParagonIE_Sodium_Compat::increment($n);
        }
    }

    public function testScalarOpMul(): void
    {
        $x = sodium_hex2bin('5698f8e0556275ac6725829dcc8505a23349c49994db45b126e4234e8e081908');
        $y = sodium_hex2bin('bf33fc4ef227d64aa6e257e544bad16b52a3185a38baa56ce21de8af97aa2606');
        $expect = '9cc7e7bdad442f9734f404a9960e7a0ca16cdbe55f322bb5c5242cfbce071606';
        $z = ParagonIE_Sodium_Compat::ristretto255_scalar_mul($x, $y);
        $this->assertSame($expect, sodium_bin2hex($z), 'scalar_mul');
    }

    /**
     * @param string $s
     * @param string $msg
     * @return void
     * @throws SodiumException
     */
    protected function assertValidPoint($s, $msg)
    {
        $this->assertTrue(
            ParagonIE_Sodium_Compat::ristretto255_is_valid_point($s, true),
            $msg
        );
    }

    /**
     * @throws SodiumException
     */
    public function testScalarMultTestVectors(): void
    {
        $k = sodium_hex2bin('40a47d219ac550a3dcd7993356cfe639ff0e0cebbce2c82dd8010597db7d305d');
        $a = sodium_hex2bin('9015dc069ae1fde7a640c8df344ae3753e691305a8e05199485c515f34d9bf13');
        $b = sodium_crypto_scalarmult_ristretto255($k, $a);
        $b2 = ParagonIE_Sodium_Compat::scalarmult_ristretto255($k, $a);
        $this->assertSame(sodium_bin2hex($b), sodium_bin2hex($b2), 'scalarmult');

        $this->assertSame(
            '082e3359857311730af327cea83026d3b1947c3a79c31aa85469c68681f14043',
            sodium_bin2hex($b)
        );
        $this->assertTrue(
            sodium_crypto_core_ristretto255_is_valid_point($b),
            'Must be a valid point'
        );

        $x = sodium_hex2bin("edf2014b8a2ca9ec18e3ba4600c3c9c48d38acebba01601ad7b104a492035b06");
        $p = sodium_crypto_scalarmult_ristretto255_base($x);
        $p2 = ParagonIE_Sodium_Compat::scalarmult_ristretto255_base($x);
        $this->assertSame(sodium_bin2hex($p), sodium_bin2hex($p2), 'scalarmult_base');
        $this->assertSame(
            '6c255b1a2ce9e9b2631d74adef073734e464c3fe8920a6950e56d77500133a49',
            sodium_bin2hex($p)
        );

        $n = sodium_hex2bin("94938bc8631c7d760f6a8b9d9c9c07569e65d9cf79dc809221186205fea3ec05");
        $r1 = sodium_crypto_scalarmult_ristretto255($n, $p);
        $r2 = ParagonIE_Sodium_Compat::scalarmult_ristretto255($n, $p);

        $this->assertSame(
            sodium_bin2hex($r1),
            sodium_bin2hex($r2)
        );
        $this->assertSame(
            'ce93b4ebe713bc0cad661b15dc022f428048e4ff78575ce29d5c333083bafc7a',
            sodium_bin2hex($r1)
        );
        $this->assertSame(
            'ce93b4ebe713bc0cad661b15dc022f428048e4ff78575ce29d5c333083bafc7a',
            sodium_bin2hex($r2)
        );
    }

    /**
     * @throws SodiumException
     */
    public function testRistretto255Operations(): void
    {
        $p = ParagonIE_Sodium_Compat::ristretto255_random();
        $q = ParagonIE_Sodium_Compat::ristretto255_random();
        $s = ParagonIE_Sodium_Compat::ristretto255_scalar_random();
        $t = ParagonIE_Sodium_Compat::ristretto255_scalar_random();

        $this->assertIsString(ParagonIE_Sodium_Compat::ristretto255_add($p, $q));
        $this->assertIsString(ParagonIE_Sodium_Compat::ristretto255_sub($p, $q));
        $this->assertIsString(ParagonIE_Sodium_Compat::ristretto255_scalar_add($s, $t));
        $this->assertIsString(ParagonIE_Sodium_Compat::ristretto255_scalar_sub($s, $t));
        $this->assertIsString(ParagonIE_Sodium_Compat::ristretto255_scalar_negate($s));
        $this->assertIsString(ParagonIE_Sodium_Compat::ristretto255_scalar_complement($s));
        $this->assertIsString(ParagonIE_Sodium_Compat::ristretto255_scalar_invert($s));
    }
}
