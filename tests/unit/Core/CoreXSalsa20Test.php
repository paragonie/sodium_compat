<?php

use PHPUnit\Framework\TestCase;

class CoreXSalsa20Test extends TestCase
{
    /**
     * @throws Exception
     * @throws SodiumException
     */
    public function testXsalsa20XorReversibility(): void
    {
        $key = random_bytes(32);
        $nonce = random_bytes(24);
        $message = 'the xsalsa20 message';

        $encrypted = ParagonIE_Sodium_Core_XSalsa20::xsalsa20_xor($message, $nonce, $key);
        $decrypted = ParagonIE_Sodium_Core_XSalsa20::xsalsa20_xor($encrypted, $nonce, $key);

        $this->assertSame($message, $decrypted);
    }

    /**
     * @throws SodiumException
     */
    public function testXsalsa20StreamVector(): void
    {
        $key = ParagonIE_Sodium_Core_Util::hex2bin(
            '1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389'
        );
        $nonce = ParagonIE_Sodium_Core_Util::hex2bin(
            '69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37'
        );
        $expectedStream = 'eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880' .
            '309e645a74e9e0a60d8243acd9177ab51a1beb8d5a2f5d700c093c5e55855796';

        $stream = ParagonIE_Sodium_Core_XSalsa20::xsalsa20(64, $nonce, $key);
        $this->assertSame($expectedStream, ParagonIE_Sodium_Core_Util::bin2hex($stream));
    }
}
