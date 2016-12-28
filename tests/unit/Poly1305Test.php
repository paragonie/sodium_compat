<?php

class Poly1305Test extends PHPUnit_Framework_TestCase
{
    /**
     * @covers ParagonIE_Sodium_Core_Poly1305::onetimeauth()
     * @ref https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#page-12
     */
    public function testVectorA()
    {
        $msg = hex2bin('0000000000000000000000000000000000000000000000000000000000000000');
        $key = hex2bin('746869732069732033322d62797465206b657920666f7220506f6c7931333035');
        $this->assertSame(
            '49ec78090e481ec6c26b33b91ccc0307',
            bin2hex(ParagonIE_Sodium_Core_Poly1305::onetimeauth($msg, $key)),
            'crypto_onetimeauth is broken'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Core_Poly1305::onetimeauth()
     * @ref https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#page-12
     */
    public function testVectorB()
    {

        $msg = hex2bin('48656c6c6f20776f726c6421');
        $key = hex2bin('746869732069732033322d62797465206b657920666f7220506f6c7931333035');
        $this->assertSame(
            'a6f745008f81c916a20dcc74eef2b2f0',
            bin2hex(ParagonIE_Sodium_Core_Poly1305::onetimeauth($msg, $key)),
            'crypto_onetimeauth is broken'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Core_Poly1305::onetimeauth_verify()
     */
    public function testRandomVerify()
    {
        $msg = random_bytes(random_int(1, 1000));
        $key = random_bytes(32);

        $mac = ParagonIE_Sodium_Core_Poly1305::onetimeauth($msg, $key);
        $this->assertTrue(
            ParagonIE_Sodium_Core_Poly1305::onetimeauth_verify($mac, $msg, $key),
            'crypto_onetimeauth_verify is broken'
        );
    }
}