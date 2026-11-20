<?php

use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class SodiumCompatCryptoMLDSA44Test extends KnownAnswerTestCase
{
    private bool $previousFallback;

    /**
     * @before
     */
    #[Before]
    public function before(): void
    {
        $this->previousFallback = ParagonIE_Sodium_Compat::$disableFallbackForUnitTests;
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @after
     */
    #[After]
    public function after(): void
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = $this->previousFallback;
    }

    /**
     * @throws JsonException
     */
    public static function vectors(): array
    {
        return PQVectorProvider::native('mldsa44');
    }

    /**
     * @dataProvider vectors
     * @throws SodiumException
     */
    #[DataProvider('vectors')]
    public function testExpandedKeypairMatchesNativeBytes(array $test): void
    {
        $keypair = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_seed_keypair(hex2bin($test['seed']));
        $this->assertSame($test['sk'] . $test['pk'], bin2hex($keypair));
        $this->assertSame($test['sk'], bin2hex(ParagonIE_Sodium_Compat::crypto_sign_mldsa44_secretkey($keypair)));
        $this->assertSame($test['pk'], bin2hex(ParagonIE_Sodium_Compat::crypto_sign_mldsa44_publickey($keypair)));
    }

    /**
     * @dataProvider vectors
     */
    #[DataProvider('vectors')]
    public function testVerifiesNativeSignature(array $test): void
    {
        $this->assertTrue(ParagonIE_Sodium_Compat::crypto_sign_mldsa44_verify_detached_ctx(
            hex2bin($test['sig']),
            hex2bin($test['msg']),
            hex2bin($test['ctx']),
            hex2bin($test['pk'])
        ));
    }

    /**
     * @dataProvider vectors
     */
    #[DataProvider('vectors')]
    public function testNativeSignatureRejectsChangedMessage(array $test): void
    {
        $this->assertFalse(ParagonIE_Sodium_Compat::crypto_sign_mldsa44_verify_detached_ctx(
            hex2bin($test['sig']),
            hex2bin($test['msg']) . "\0",
            hex2bin($test['ctx']),
            hex2bin($test['pk'])
        ));
    }

    /**
     * @dataProvider vectors
     */
    #[DataProvider('vectors')]
    public function testNativeSignatureRejectsChangedContext(array $test): void
    {
        $context = hex2bin($test['ctx']);
        $context = $context === '' ? 'different context' : $context;
        $context[0] = $context[0] ^ "\x01";
        $this->assertFalse(ParagonIE_Sodium_Compat::crypto_sign_mldsa44_verify_detached_ctx(
            hex2bin($test['sig']),
            hex2bin($test['msg']),
            $context,
            hex2bin($test['pk'])
        ));
    }
}
