<?php

use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(ParagonIE_Sodium_Core_AES::class)]
class AESTest extends TestCase
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
     * @return array[]
     * @link https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf
     * @link https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core128.pdf
     */
    public static function aes128ecbProvider(): array
    {
        // key, plaintext, ciphertext
        return array(
            array(
                "2B7E151628AED2A6ABF7158809CF4F3C",
                "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710",
                "3AD77BB40D7A3660A89ECAF32466EF97F5D3D58503B9699DE785895A96FDBAAF43B1CD7F598ECE23881B00E3ED0306887B0C785E27E8AD3F8223207104725DD4"
            ),
            array("000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"),
            array('30313233343536373839616263646566', '59454c4c4f57205355424d4152494e45', '1438c8f442ce85508d6b1f6826988551'),
            array('00000000000000000000000000000000', 'f34481ec3cc627bacd5dc3fb08f273e6', '0336763e966d92595a567cc9ce537f5e'),
            array('00000000000000000000000000000000', '9798c4640bad75c7c3227db910174e72', 'a9a1631bf4996954ebc093957b234589'),
            array('00000000000000000000000000000000', '96ab5c2ff612d9dfaae8c31f30c42168', 'ff4f8391a6a40ca5b25d23bedd44a597'),
            array('00000000000000000000000000000000', '6a118a874519e64e9963798a503f1d35', 'dc43be40be0e53712f7e2bf5ca707209'),
            array('00000000000000000000000000000000', 'cb9fceec81286ca3e989bd979b0cb284', '92beedab1895a94faa69b632e5cc47ce'),
            array('00000000000000000000000000000000', 'b26aeb1874e47ca8358ff22378f09144', '459264f4798f6a78bacb89c15ed3d601'),
            array('00000000000000000000000000000000', '58c8e00b2631686d54eab84b91f0aca1', '08a4e2efec8a8e3312ca7460b9040bbf')
        );
    }

    /**
     * @link https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core192.pdf
     */
    public static function aes192ecbProvider(): array
    {
        // key, plaintext, ciphertext
        return array(
            array(
                "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B",
                "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710",
                "BD334F1D6E45F25FF712A214571FA5CC974104846D0AD3AD7734ECB3ECEE4EEFEF7AFD2270E2E60ADCE0BA2FACE6444E9A4B41BA738D6C72FB16691603C18E0E"
            ),
        );
    }

    /**
     * @link https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core256.pdf
     */
    public static function aes256ecbProvider(): array
    {
        // key, plaintext, ciphertext
        return array(
            array(
                "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4",
                "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710",
                "F3EED1BDB5D2A03C064B5A7E3DB181F8591CCB10D410ED26DC5BA74A31362870B6ED21B99CA6F4F9F153E7B1BEAFED1D23304B7A39F9F3FF067D8D8F9E24ECC7"
            ),
        );
    }

    public static function sboxProvider(): array
    {
        $lut = array(
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
            0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
            0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
            0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
            0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
            0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
            0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
            0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
            0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
            0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
            0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
            0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
            0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
            0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
            0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
            0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
            0xB0, 0x54, 0xBB, 0x16
        );
        $return = array();
        foreach ($lut as $i => $v) {
            $return []= array($i, $v);
        }
        return $return;
    }

    public function testSboxKnownGood(): void
    {
        $q = ParagonIE_Sodium_Core_AES_Block::fromArray(array(
            0x00010203,
            0x04050607,
            0x08090a0b,
            0x0c0d0e0f,
            0x89697676, // YELL
            0x79872083, // OW S
            0x85667765, // UBMA
            0x82737869, // RINE
        ));
        $q->orthogonalize();
        ParagonIE_Sodium_Core_AES::sbox($q);
        $q->orthogonalize();
        $this->assertSame('637c777b', dechex($q[0]));
    }

    /**
     * @dataProvider sboxProvider
     */
    #[DataProvider("sboxProvider")]
    public function testSBox($input, $expected): void
    {
        $q = ParagonIE_Sodium_Core_AES_Block::init();
        for ($i = 0; $i < 8; ++$i) {
            $q[$i] = ($input | ($input << 8) | ($input << 16) | ($input << 24)) & ParagonIE_Sodium_Core_Util::U32_MAX;
        }

        $q->orthogonalize();
        ParagonIE_Sodium_Core_AES::sbox($q);
        $q->orthogonalize();

        $this->assertSame(dechex($expected), dechex($q[0] & 0xff));
        $this->assertSame($expected, $q[0] & 0xff);

        $q2 = clone $q;
        $q2->orthogonalize();
        ParagonIE_Sodium_Core_AES::invSbox($q2);
        $q2->orthogonalize();
        for ($i = 0; $i < 8; ++$i) {
            $x = ($input | ($input << 8) | ($input << 16) | ($input << 24)) & ParagonIE_Sodium_Core_Util::U32_MAX;
            $this->assertSame($x, $q2[$i]);
        }
    }

    public static function orthoProvider(): array
    {
        return array(
            array(
                array(0x03020100, 0x03020100, 0x07060504, 0x07060504, 0x0b0a0908, 0x0b0a0908, 0x0f0e0d0c, 0x0f0e0d0c),
                array(0xff00ff00, 0xffff0000, 0xcccccccc, 0xf0f0f0f0, 0x00000000, 0x00000000, 0x00000000, 0x00000000)
            ),
            array(
                array(0xfd74aad6, 0xfd74aad6, 0xfa72afd2, 0xfa72afd2, 0xf178a6da, 0xf178a6da, 0xfe76abd6, 0xfe76abd6),
                array(0x3300cc00, 0xccccffff, 0xc3c33cc3, 0xcf30cf30, 0xffff00ff, 0xffffff00, 0xffff00ff, 0xff00ffff)
            )
        );
    }

    /**
     * @dataProvider orthoProvider
     */
    #[DataProvider("orthoProvider")]
    public function testOrtho(array $input, array $expected): void
    {
        $q = ParagonIE_Sodium_Core_AES_Block::fromArray($input);
        $q->orthogonalize();
        for ($i = 0; $i < 8; ++$i) {
            $this->assertSame($expected[$i], $q[$i], 'ortogonalize test');
        }
    }

    public function testAddRoundKey(): void
    {
        $q = ParagonIE_Sodium_Core_AES_Block::fromArray(array(1, 2, 3, 4, 5, 6, 7, 8));
        $schedule = ParagonIE_Sodium_Core_AES::keySchedule('sodiumcompat1.21');
        ParagonIE_Sodium_Core_AES::addRoundKey($q, $schedule);
        $rk = $schedule->getRoundKey(0);
        for ($i = 0; $i < 8; ++$i) {
            $this->assertSame($rk[$i] ^ ($i + 1), $q[$i]);
        }
    }

    public function testShiftRows(): void
    {
        $q = ParagonIE_Sodium_Core_AES_Block::fromArray(array(
            0x11111111, 0x22222222, 0x33333333, 0x44444444,
            0x01234567, 0xfedcba98, 0x00010203, 0xfffefdfc,
        ));
        $_q = clone $q;
        $q->orthogonalize()->shiftRows()->orthogonalize();
        $this->assertSame(0x00233311, $q[0]);

        // Ensure the inverse operation is valid
        $q->orthogonalize()->inverseShiftRows()->orthogonalize();
        for ($i = 0; $i < 8; ++$i) {
            $this->assertSame($_q[$i], $q[$i]);
        }
    }

    public function testSubWord(): void
    {
        $this->assertSame(0xfe76abd7, ParagonIE_Sodium_Core_AES::subWord(0x0c0f0e0d));
    }

    public function testMixColumns(): void
    {
        $q = ParagonIE_Sodium_Core_AES_Block::fromArray(array(
            0xf8be2b17, 0xcaba63cb, 0x67b2a090, 0x8988c2d4, 0x1a70b1e8, 0xcabf96eb, 0x7ae7f79b, 0x615d60d8
        ));
        $q->mixColumns();

        $this->assertSame(0x3bf86cd5, $q[0]);
        $this->assertSame(0x44181397, $q[1]);
        $this->assertSame(0x83279cdd, $q[2]);
        $this->assertSame(0xd076fa4b, $q[3]);
        $this->assertSame(0xcd7ef575, $q[4]);
        $this->assertSame(0x30dd5fba, $q[5]);
        $this->assertSame(0xaa632f17, $q[6]);
        $this->assertSame(0x0444f430, $q[7]);

        $q->inverseMixColumns();

        $this->assertSame(0xf8be2b17, $q[0]);
        $this->assertSame(0xcaba63cb, $q[1]);
        $this->assertSame(0x67b2a090, $q[2]);
        $this->assertSame(0x8988c2d4, $q[3]);
        $this->assertSame(0x1a70b1e8, $q[4]);
        $this->assertSame(0xcabf96eb, $q[5]);
        $this->assertSame(0x7ae7f79b, $q[6]);
        $this->assertSame(0x615d60d8, $q[7]);
    }

    public function testKeySchedule(): void
    {
        $ks = ParagonIE_Sodium_Core_AES::keySchedule(sodium_hex2bin("000102030405060708090a0b0c0d0e0f"));
        $expect = array(
            0xffaa5500, 0xe4e4e4e4, 0x00000000, 0x00000000, 0x9988eeaa, 0xcb619e61, 0xffffaa55, 0xff55aaff,
            0x87d73622, 0xc21f2cb5, 0xccccddbb, 0xccbb2266, 0x7ec45b0a, 0x3ff9a371, 0x3cc39327, 0x698d5f1e,
            0x4c6b4757, 0xf3cd75e5, 0xf33f2ff4, 0xe28313f9, 0xbcb7be44, 0x9a3c4ecb, 0x9aa6f69b, 0x9f2afa98,
            0xd9dbd9be, 0x87f31697, 0x87749b2d, 0x7908982d, 0x92386d8c, 0x7e30aed1, 0x811b8709, 0x18fd875c,
            0x85a7e383, 0x19a5dcc5, 0x7ff8d4a8, 0xf86681b9, 0x81de3580, 0xf874c6c1, 0x196791dd, 0x67b42a8d,
            0x7f39f17f, 0x671b94c0, 0x07e18539, 0xe124087c, 0xae3e1b15, 0x258d57b9, 0xfdc705c5, 0xf8ed6a99,
            0x4cf0d767, 0xed0ccc30, 0xf42551fb, 0xa7ed7a77, 0xf26bc1e0, 0xd7e69659, 0x2a21939c, 0xd2ccf905,
            0x4769bcd2, 0xaa6570e2, 0x5e402119, 0xf9ad5b6e
        );
        for ($i = 0; $i < 44; ++$i) {
            $this->assertSame(
                sprintf('0x%08x', $expect[$i]),
                sprintf('0x%08x', $ks->get($i)),
                'key schedule u = ' . $i
            );
            $this->assertSame($expect[$i], $ks->get($i), 'key schedule u = ' . $i);
        }
        $sk_expect = array(
            0xff00ff00, 0xffff0000, 0xcccccccc, 0xf0f0f0f0, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x3300cc00, 0xccccffff, 0xc3c33cc3, 0xcf30cf30, 0xffff00ff, 0xffffff00, 0xffff00ff, 0xff00ffff,
            0x0fff3c00, 0xc3c33333, 0xc03f0c3f, 0xc30f3cf0, 0xccccff33, 0xccccccff, 0xcc3300cc, 0xccff3333,
            0xfcccf300, 0x3fc00f0f, 0x3ff303f3, 0x3ffcf330, 0x3cc3330f, 0x3cc3c333, 0xc30fff3c, 0x3ccc0f0f,
            0xccc3cfff, 0x0c3f0303, 0xf3cfffcf, 0xf3cc30f0, 0xf33f0ffc, 0xf33f3ff0, 0xc00333f3, 0xf3c303fc,
            0x3c3f3ccc, 0xfcf3ff00, 0x303cccc3, 0xcf3c0fcf, 0x300cfc33, 0xcff3f3cf, 0x3f00f030, 0xcf3fffcc,
            0xf3f3f33c, 0xcccfccff, 0x0ff33c3f, 0xc3f303c3, 0x0ffc330f, 0xc330cf3c, 0xf300300f, 0x3c0ccc3c,
            0x3030cf0c, 0xc33c3ccc, 0xfc300cf3, 0x3f30ffc0, 0x03330f03, 0xc00fc30c, 0x30ff0ffc, 0x0cfcc30c,
            0x0f0fc303, 0xc0f3f3c3, 0x330ffccf, 0x0cf0ccc0, 0xfff0fc00, 0x3ffcc0fc, 0xf0cc0333, 0xfc33c0fc,
            0x03fc3f00, 0xc0cf30c0, 0xf0fcccc3, 0xfc30c3c0, 0x33cf33ff, 0x0c33c0cc, 0xcf3c000f, 0x33f03fcc,
            0xff33f3ff, 0x3f3cf03f, 0xcf333cc0, 0x330fc0c0, 0x0fc30f33, 0x03f0c03c, 0xc30c00fc, 0xf0300c3c,
            0xb828aeed, 0x00007f2b, 0x00000006, 0x00000000, 0xb841b780, 0x00007f2b, 0x0000000d, 0x00000000,
            0x0f6832a0, 0x0000558a, 0x00000d68, 0x00000000, 0xb828c9e1, 0x00007f2b, 0xb841b780, 0x00007f2b,
            0xb841b780, 0x00007f2b, 0xb8417600, 0x00007f2b, 0x03c1dbd8, 0x00007ffd, 0x0e840083, 0x0000558a,
            0x0e87b7d8, 0x0000558a, 0xb858e040, 0x00007f2b, 0x77160b00, 0x852ca90b, 0x0e83a0e7, 0x0000558a
        );
        $expanded = $ks->expand();
        for ($i = 0; $i < 44; ++$i) {
            $this->assertSame(
                sprintf('0x%08x', $sk_expect[$i]),
                sprintf('0x%08x', $expanded->get($i)),
                'key schedule u = ' . $i
            );
            $this->assertSame($expect[$i], $ks->get($i), 'key schedule u = ' . $i);
        }
    }

    public function testSkeyExpand(): void
    {
        // "000102030405060708090a0b0c0d0e0f"
        $ks = new ParagonIE_Sodium_Core_AES_KeySchedule(array(
            0xffaa5500, 0xe4e4e4e4, 0x00000000, 0x00000000, 0x9988eeaa, 0xcb619e61, 0xffffaa55, 0xff55aaff,
            0x87d73622, 0xc21f2cb5, 0xccccddbb, 0xccbb2266, 0x7ec45b0a, 0x3ff9a371, 0x3cc39327, 0x698d5f1e,
            0x4c6b4757, 0xf3cd75e5, 0xf33f2ff4, 0xe28313f9, 0xbcb7be44, 0x9a3c4ecb, 0x9aa6f69b, 0x9f2afa98,
            0xd9dbd9be, 0x87f31697, 0x87749b2d, 0x7908982d, 0x92386d8c, 0x7e30aed1, 0x811b8709, 0x18fd875c,
            0x85a7e383, 0x19a5dcc5, 0x7ff8d4a8, 0xf86681b9, 0x81de3580, 0xf874c6c1, 0x196791dd, 0x67b42a8d,
            0x7f39f17f, 0x671b94c0, 0x07e18539, 0xe124087c
        ), 10);
        $exp = $ks->expand();
        $values = array(
            0xff00ff00, 0xffff0000, 0xcccccccc, 0xf0f0f0f0, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x3300cc00, 0xccccffff, 0xc3c33cc3, 0xcf30cf30, 0xffff00ff, 0xffffff00, 0xffff00ff, 0xff00ffff,
            0x0fff3c00, 0xc3c33333, 0xc03f0c3f, 0xc30f3cf0, 0xccccff33, 0xccccccff, 0xcc3300cc, 0xccff3333,
            0xfcccf300, 0x3fc00f0f, 0x3ff303f3, 0x3ffcf330, 0x3cc3330f, 0x3cc3c333, 0xc30fff3c, 0x3ccc0f0f,
            0xccc3cfff, 0x0c3f0303, 0xf3cfffcf, 0xf3cc30f0, 0xf33f0ffc, 0xf33f3ff0, 0xc00333f3, 0xf3c303fc,
            0x3c3f3ccc, 0xfcf3ff00, 0x303cccc3, 0xcf3c0fcf, 0x300cfc33, 0xcff3f3cf, 0x3f00f030, 0xcf3fffcc,
            0xf3f3f33c, 0xcccfccff, 0x0ff33c3f, 0xc3f303c3, 0x0ffc330f, 0xc330cf3c, 0xf300300f, 0x3c0ccc3c,
            0x3030cf0c, 0xc33c3ccc, 0xfc300cf3, 0x3f30ffc0, 0x03330f03, 0xc00fc30c, 0x30ff0ffc, 0x0cfcc30c,
            0x0f0fc303, 0xc0f3f3c3, 0x330ffccf, 0x0cf0ccc0, 0xfff0fc00, 0x3ffcc0fc, 0xf0cc0333, 0xfc33c0fc,
            0x03fc3f00, 0xc0cf30c0, 0xf0fcccc3, 0xfc30c3c0, 0x33cf33ff, 0x0c33c0cc, 0xcf3c000f, 0x33f03fcc,
            0xff33f3ff, 0x3f3cf03f, 0xcf333cc0, 0x330fc0c0, 0x0fc30f33, 0x03f0c03c, 0xc30c00fc, 0xf0300c3c
        );
        for ($i = 0; $i < 88; ++$i) {
            $this->assertSame($values[$i], $exp->get($i), 'skey - index ' . $i);
        }
    }

    public function testAesRound(): void
    {
        $in = ParagonIE_Sodium_Core_Util::hex2bin('000102030405060708090a0b0c0d0e0f');
        $rk = ParagonIE_Sodium_Core_Util::hex2bin('101112131415161718191a1b1c1d1e1f');
        $this->assertSame(
            '7a7b4e5638782546a8c0477a3b813f43',
            ParagonIE_Sodium_Core_Util::bin2hex(
                ParagonIE_Sodium_Core_AES::aesRound($in, $rk)
            )
        );
    }

    /**
     * @throws Exception
     */
    public function testAesDoubleRound(): void
    {
        $in = ParagonIE_Sodium_Core_Util::hex2bin('000102030405060708090a0b0c0d0e0f');
        $rk = ParagonIE_Sodium_Core_Util::hex2bin('101112131415161718191a1b1c1d1e1f');
        $this->assertSame(
            '7a7b4e5638782546a8c0477a3b813f437a7b4e5638782546a8c0477a3b813f43',
            ParagonIE_Sodium_Core_Util::bin2hex(
                implode('', ParagonIE_Sodium_Core_AES::doubleRound($in, $rk, $in, $rk))
            )
        );

        // Let's randomize this to test equivalence.
        $in0 = random_bytes(16);
        $in1 = random_bytes(16);
        $rk0 = random_bytes(16);
        $rk1 = random_bytes(16);

        $c0 = ParagonIE_Sodium_Core_AES::aesRound($in0, $rk0);
        $c1 = ParagonIE_Sodium_Core_AES::aesRound($in1, $rk1);
        list($c2, $c3) = ParagonIE_Sodium_Core_AES::doubleRound($in0, $rk0, $in1, $rk1);
        $this->assertSame(
            ParagonIE_Sodium_Core_Util::bin2hex($c0),
            ParagonIE_Sodium_Core_Util::bin2hex($c2)
        );
        $this->assertSame(
            ParagonIE_Sodium_Core_Util::bin2hex($c1),
            ParagonIE_Sodium_Core_Util::bin2hex($c3)
        );
    }

    /**
     * @dataProvider aes128ecbProvider
     */
    #[DataProvider("aes128ecbProvider")]
    public function testEncryptBlock128ECB($key_hex, $pt_hex, $ct_hex): void
    {
        $key = ParagonIE_Sodium_Core_Util::hex2bin($key_hex);

        for ($i = 0; $i < strlen($pt_hex); $i += 32) {
            $pt = ParagonIE_Sodium_Core_Util::hex2bin(substr($pt_hex, $i, 32));
            $ct = ParagonIE_Sodium_Core_Util::hex2bin(substr($ct_hex, $i, 32));
            $actual = ParagonIE_Sodium_Core_AES::encryptBlockECB($pt, $key);
            $this->assertSame($actual, $ct, 'AES-128 test vector failed (encryption)');
            $decrypted = ParagonIE_Sodium_Core_AES::decryptBlockECB($ct, $key);
            $this->assertSame($decrypted, $pt, 'AES-128 test vector failed (decryption)');
        }
    }
    /**
     * @dataProvider aes192ecbProvider
     */
    #[DataProvider("aes192ecbProvider")]
    public function testEncryptBlock192ECB($key_hex, $pt_hex, $ct_hex): void
    {
        $key = ParagonIE_Sodium_Core_Util::hex2bin($key_hex);

        for ($i = 0; $i < strlen($pt_hex); $i += 32) {
            $pt = ParagonIE_Sodium_Core_Util::hex2bin(substr($pt_hex, $i, 32));
            $ct = ParagonIE_Sodium_Core_Util::hex2bin(substr($ct_hex, $i, 32));
            $actual = ParagonIE_Sodium_Core_AES::encryptBlockECB($pt, $key);
            $this->assertSame($actual, $ct, 'AES-192 test vector failed (encryption)');
            $decrypted = ParagonIE_Sodium_Core_AES::decryptBlockECB($ct, $key);
            $this->assertSame($decrypted, $pt, 'AES-192 test vector failed (decryption)');
        }
    }

    /**
     * @dataProvider aes256ecbProvider
     */
    #[DataProvider("aes256ecbProvider")]
    public function testEncryptBlock256ECB($key_hex, $pt_hex, $ct_hex): void
    {
        $key = ParagonIE_Sodium_Core_Util::hex2bin($key_hex);

        for ($i = 0; $i < strlen($pt_hex); $i += 32) {
            $pt = ParagonIE_Sodium_Core_Util::hex2bin(substr($pt_hex, $i, 32));
            $ct = ParagonIE_Sodium_Core_Util::hex2bin(substr($ct_hex, $i, 32));
            $actual = ParagonIE_Sodium_Core_AES::encryptBlockECB($pt, $key);
            $this->assertSame($actual, $ct, 'AES-256 test vector failed (encryption)');
            $decrypted = ParagonIE_Sodium_Core_AES::decryptBlockECB($ct, $key);
            $this->assertSame($decrypted, $pt, 'AES-256 test vector failed (decryption)');
        }
    }
}
