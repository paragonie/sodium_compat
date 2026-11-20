<?php

use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class SodiumCompatCryptoMLKEM768Test extends KnownAnswerTestCase
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

    public static function vectors(): array
    {
        return PQVectorProvider::native('mlkem768');
    }

    /**
     * @dataProvider vectors
     * @throws SodiumException
     */
    #[DataProvider('vectors')]
    public function testSeedKeypairBytes(array $test): void
    {
        $keypair = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_seed_keypair(hex2bin($test['seed']));
        $this->assertSame($test['sk'] . $test['pk'], bin2hex($keypair));
        $this->assertSame($test['sk'], bin2hex(ParagonIE_Sodium_Compat::crypto_kem_mlkem768_secretkey($keypair)));
        $this->assertSame($test['pk'], bin2hex(ParagonIE_Sodium_Compat::crypto_kem_mlkem768_publickey($keypair)));
    }

    /**
     * @dataProvider vectors
     * @throws SodiumException
     */
    #[DataProvider('vectors')]
    public function testDeterministicEncapsulationBytes(array $test): void
    {
        $result = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_enc_deterministic(
            hex2bin($test['pk']),
            hex2bin($test['randomness'])
        );
        $this->assertSame($test['ct'], bin2hex($result[0]));
        $this->assertSame($test['ss'], bin2hex($result[1]));
    }

    /**
     * @dataProvider vectors
     * @throws SodiumException
     */
    #[DataProvider('vectors')]
    public function testDecapsulationBytes(array $test): void
    {
        $this->assertSame($test['ss'], bin2hex(
            ParagonIE_Sodium_Compat::crypto_kem_mlkem768_dec(hex2bin($test['ct']), hex2bin($test['sk']))
        ));
    }

    /**
     * @dataProvider vectors
     * @throws SodiumException
     */
    #[DataProvider('vectors')]
    public function testImplicitRejectionMatchesNativeReference(array $test): void
    {
        $ciphertext = hex2bin($test['ct']);
        $ciphertext[0] = $ciphertext[0] ^ "\x01";
        $this->assertSame($test['rejected'], bin2hex(
            ParagonIE_Sodium_Compat::crypto_kem_mlkem768_dec($ciphertext, hex2bin($test['sk']))
        ));
    }
}
