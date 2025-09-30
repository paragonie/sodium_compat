<?php

use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\TestCase;

class Poly1305Test extends TestCase
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
     * @ref https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#page-12
     */
    public function testVectorA(): void
    {
        $msg = ParagonIE_Sodium_Core_Util::hex2bin('0000000000000000000000000000000000000000000000000000000000000000');
        $key = ParagonIE_Sodium_Core_Util::hex2bin('746869732069732033322d62797465206b657920666f7220506f6c7931333035');
        $this->assertSame(
            '49ec78090e481ec6c26b33b91ccc0307',
            bin2hex(
                ParagonIE_Sodium_Core_Poly1305::onetimeauth($msg, $key)
            ),
            'crypto_onetimeauth is broken'
        );
    }

    /**
     * @ref https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#page-12
     */
    public function testVectorB(): void
    {
        $msg = ParagonIE_Sodium_Core_Util::hex2bin('48656c6c6f20776f726c6421');
        $key = ParagonIE_Sodium_Core_Util::hex2bin('746869732069732033322d62797465206b657920666f7220506f6c7931333035');
        $this->assertSame(
            'a6f745008f81c916a20dcc74eef2b2f0',
            ParagonIE_Sodium_Core_Util::bin2hex(
                ParagonIE_Sodium_Core_Poly1305::onetimeauth($msg, $key)
            ),
            'crypto_onetimeauth is broken'
        );
    }

    /**
     * A large message test vector.
     *
     * @ref https://github.com/jedisct1/libsodium/blob/master/test/default/onetimeauth2.c
     */
    public function testVectorC(): void
    {
        $msg = ParagonIE_Sodium_Core_Util::intArrayToString(
            array(
                0x8e, 0x99, 0x3b, 0x9f, 0x48, 0x68, 0x12, 0x73, 0xc2, 0x96, 0x50, 0xba,
                0x32, 0xfc, 0x76, 0xce, 0x48, 0x33, 0x2e, 0xa7, 0x16, 0x4d, 0x96, 0xa4,
                0x47, 0x6f, 0xb8, 0xc5, 0x31, 0xa1, 0x18, 0x6a, 0xc0, 0xdf, 0xc1, 0x7c,
                0x98, 0xdc, 0xe8, 0x7b, 0x4d, 0xa7, 0xf0, 0x11, 0xec, 0x48, 0xc9, 0x72,
                0x71, 0xd2, 0xc2, 0x0f, 0x9b, 0x92, 0x8f, 0xe2, 0x27, 0x0d, 0x6f, 0xb8,
                0x63, 0xd5, 0x17, 0x38, 0xb4, 0x8e, 0xee, 0xe3, 0x14, 0xa7, 0xcc, 0x8a,
                0xb9, 0x32, 0x16, 0x45, 0x48, 0xe5, 0x26, 0xae, 0x90, 0x22, 0x43, 0x68,
                0x51, 0x7a, 0xcf, 0xea, 0xbd, 0x6b, 0xb3, 0x73, 0x2b, 0xc0, 0xe9, 0xda,
                0x99, 0x83, 0x2b, 0x61, 0xca, 0x01, 0xb6, 0xde, 0x56, 0x24, 0x4a, 0x9e,
                0x88, 0xd5, 0xf9, 0xb3, 0x79, 0x73, 0xf6, 0x22, 0xa4, 0x3d, 0x14, 0xa6,
                0x59, 0x9b, 0x1f, 0x65, 0x4c, 0xb4, 0x5a, 0x74, 0xe3, 0x55, 0xa5
            )
        );
        ;
        $key = ParagonIE_Sodium_Core_Util::intArrayToString(
            array(
                0xee, 0xa6, 0xa7, 0x25, 0x1c, 0x1e, 0x72, 0x91, 0x6d, 0x11, 0xc2,
                0xcb, 0x21, 0x4d, 0x3c, 0x25, 0x25, 0x39, 0x12, 0x1d, 0x8e, 0x23,
                0x4e, 0x65, 0x2d, 0x65, 0x1f, 0xa4, 0xc8, 0xcf, 0xf8, 0x80
            )
        );
        $tag = ParagonIE_Sodium_Core_Util::intArrayToString(
            array(
                0xf3, 0xff, 0xc7, 0x70, 0x3f, 0x94, 0x00, 0xe5,
                0x2a, 0x7d, 0xfb, 0x4b, 0x3d, 0x33, 0x05, 0xd9
            )
        );

        $this->assertSame(
            bin2hex($tag),
            bin2hex(
                ParagonIE_Sodium_Core_Poly1305::onetimeauth($msg, $key)
            ),
            'crypto_onetimeauth is broken -- IETF test vector'
        );
        $this->assertTrue(
            ParagonIE_Sodium_Core_Poly1305::onetimeauth_verify($tag, $msg, $key),
            'crypto_onetimeauth_verify is broken -- IETF test vector'
        );
    }

    public function testOdd(): void
    {
        $msg = str_repeat('a', 29);
        $key = ParagonIE_Sodium_Core_Util::hex2bin('69d5eae6e17623da87404bc791a408dfb1be300f43e10b96876134d5537dfcff');
        $this->assertSame(
            '1e57d95d70615c7a83a02e1156ef217c',
            bin2hex(
                ParagonIE_Sodium_Core_Poly1305::onetimeauth($msg, $key)
            ),
            'Weird message length'
        );
    }

    public function testEmpty(): void
    {

        $msg = ParagonIE_Sodium_Core_Util::hex2bin('00');
        $key = ParagonIE_Sodium_Core_Util::hex2bin('746869732069732033322d62797465206b657920666f7220506f6c7931333035');
        $this->assertSame(
            '6bd9e189698fdb93509f9ea633aba49a',
            bin2hex(
                ParagonIE_Sodium_Core_Poly1305::onetimeauth($msg, $key)
            ),
            'null byte message'
        );

        $msg = '';
        $key = ParagonIE_Sodium_Core_Util::hex2bin('746869732069732033322d62797465206b657920666f7220506f6c7931333035');
        $this->assertSame(
            '6b657920666f7220506f6c7931333035',
            bin2hex(
                ParagonIE_Sodium_Core_Poly1305::onetimeauth($msg, $key)
            ),
            'Empty message'
        );

        $msg = ParagonIE_Sodium_Core_Util::hex2bin('00');
        $this->assertSame(
            '6bd9e189698fdb93509f9ea633aba49a',
            bin2hex(
                ParagonIE_Sodium_Core_Poly1305::onetimeauth($msg, $key)
            ),
            'null byte message'
        );

        $msg = ParagonIE_Sodium_Core_Util::hex2bin('0000');
        $this->assertSame(
            'e865ed88cf729289c36f9cab5e35a8a9',
            bin2hex(
                ParagonIE_Sodium_Core_Poly1305::onetimeauth($msg, $key)
            ),
            'double null byte message'
        );
        $msg = ParagonIE_Sodium_Core_Util::hex2bin('00000000000000000000000000000000');
        $this->assertSame(
            'fc27bd24ceb202210cee247cc704af35',
            bin2hex(
                ParagonIE_Sodium_Core_Poly1305::onetimeauth($msg, $key)
            ),
            '16 null byte message'
        );
    }

    /**
     * @throws SodiumException
     */
    public function testRandomVerify(): void
    {
        $msg = random_bytes(random_int(1, 1000));
        $key = random_bytes(32);

        $mac = ParagonIE_Sodium_Core_Poly1305::onetimeauth($msg, $key);
        $this->assertTrue(
            ParagonIE_Sodium_Core_Poly1305::onetimeauth_verify($mac, $msg, $key),
            'crypto_onetimeauth_verify is broken'
        );
    }

    /**
     * @throws SodiumException
     */
    public function testOneTimeAuthInvalidKey(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Key must be 32 bytes long.');
        ParagonIE_Sodium_Core_Poly1305::onetimeauth('test message', 'short key');
    }

    /**
     * @throws SodiumException
     */
    public function testOneTimeAuthVerifyInvalidKey(): void
    {
        $mac = random_bytes(16);
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Key must be 32 bytes long.');
        ParagonIE_Sodium_Core_Poly1305::onetimeauth_verify($mac, 'test message', 'short key');
    }
}
