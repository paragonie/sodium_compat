<?php

require_once dirname(dirname(__FILE__)) . '/PQVectorProvider.php';
require_once dirname(__FILE__) . '/KnownAnswerTestCase.php';

/**
 * @covers ParagonIE_Sodium_Compat
 */
class SodiumCompatCryptoMLDSA44Test extends KnownAnswerTestCase
{
    private $previousFallback;

    /**
     * @before
     */
    public function before()
    {
        $this->previousFallback = ParagonIE_Sodium_Compat::$disableFallbackForUnitTests;
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @after
     */
    public function after()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = $this->previousFallback;
    }

    /**
     * @throws JsonException
     */
    public static function vectors()
    {
        return PQVectorProvider::native('mldsa44');
    }

    /**
     * @dataProvider vectors
     * @throws SodiumException
     */
    public function testExpandedKeypairMatchesNativeBytes(array $test)
    {
        $keypair = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_seed_keypair(ParagonIE_Sodium_Compat::hex2bin($test['seed']));
        $this->assertSame($test['sk'] . $test['pk'], bin2hex($keypair));
        $this->assertSame($test['sk'], bin2hex(ParagonIE_Sodium_Compat::crypto_sign_mldsa44_secretkey($keypair)));
        $this->assertSame($test['pk'], bin2hex(ParagonIE_Sodium_Compat::crypto_sign_mldsa44_publickey($keypair)));
    }

    /**
     * @dataProvider vectors
     */
    public function testVerifiesNativeSignature(array $test)
    {
        $this->assertTrue(ParagonIE_Sodium_Compat::crypto_sign_mldsa44_verify_detached_ctx(
            ParagonIE_Sodium_Compat::hex2bin($test['sig']),
            ParagonIE_Sodium_Compat::hex2bin($test['msg']),
            ParagonIE_Sodium_Compat::hex2bin($test['ctx']),
            ParagonIE_Sodium_Compat::hex2bin($test['pk'])
        ));
    }

    /**
     * @dataProvider vectors
     */
    public function testNativeSignatureRejectsChangedMessage(array $test)
    {
        $this->assertFalse(ParagonIE_Sodium_Compat::crypto_sign_mldsa44_verify_detached_ctx(
            ParagonIE_Sodium_Compat::hex2bin($test['sig']),
            ParagonIE_Sodium_Compat::hex2bin($test['msg']) . "\0",
            ParagonIE_Sodium_Compat::hex2bin($test['ctx']),
            ParagonIE_Sodium_Compat::hex2bin($test['pk'])
        ));
    }

    /**
     * @dataProvider vectors
     */
    public function testNativeSignatureRejectsChangedContext(array $test)
    {
        $context = ParagonIE_Sodium_Compat::hex2bin($test['ctx']);
        $context = $context === '' ? 'different context' : $context;
        $context[0] = $context[0] ^ "\x01";
        $this->assertFalse(ParagonIE_Sodium_Compat::crypto_sign_mldsa44_verify_detached_ctx(
            ParagonIE_Sodium_Compat::hex2bin($test['sig']),
            ParagonIE_Sodium_Compat::hex2bin($test['msg']),
            $context,
            ParagonIE_Sodium_Compat::hex2bin($test['pk'])
        ));
    }
}
