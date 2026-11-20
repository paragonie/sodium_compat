<?php

require_once dirname(dirname(__FILE__)) . '/PQVectorProvider.php';
require_once dirname(__FILE__) . '/KnownAnswerTestCase.php';

/**
 * @covers ParagonIE_Sodium_Compat
 */
class SodiumCompatCryptoMLKEM768Test extends KnownAnswerTestCase
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

    public static function vectors()
    {
        return PQVectorProvider::native('mlkem768');
    }

    /**
     * @dataProvider vectors
     * @throws SodiumException
     */
    public function testSeedKeypairBytes(array $test)
    {
        $keypair = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_seed_keypair(ParagonIE_Sodium_Compat::hex2bin($test['seed']));
        $this->assertSame($test['sk'] . $test['pk'], bin2hex($keypair));
        $this->assertSame($test['sk'], bin2hex(ParagonIE_Sodium_Compat::crypto_kem_mlkem768_secretkey($keypair)));
        $this->assertSame($test['pk'], bin2hex(ParagonIE_Sodium_Compat::crypto_kem_mlkem768_publickey($keypair)));
    }

    /**
     * @dataProvider vectors
     * @throws SodiumException
     */
    public function testDeterministicEncapsulationBytes(array $test)
    {
        $result = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_enc_deterministic(
            ParagonIE_Sodium_Compat::hex2bin($test['pk']),
            ParagonIE_Sodium_Compat::hex2bin($test['randomness'])
        );
        $this->assertSame($test['ct'], bin2hex($result[0]));
        $this->assertSame($test['ss'], bin2hex($result[1]));
    }

    /**
     * @dataProvider vectors
     * @throws SodiumException
     */
    public function testDecapsulationBytes(array $test)
    {
        $this->assertSame($test['ss'], bin2hex(
            ParagonIE_Sodium_Compat::crypto_kem_mlkem768_dec(ParagonIE_Sodium_Compat::hex2bin($test['ct']), ParagonIE_Sodium_Compat::hex2bin($test['sk']))
        ));
    }

    /**
     * @dataProvider vectors
     * @throws SodiumException
     */
    public function testImplicitRejectionMatchesNativeReference(array $test)
    {
        $ciphertext = ParagonIE_Sodium_Compat::hex2bin($test['ct']);
        $ciphertext[0] = $ciphertext[0] ^ "\x01";
        $this->assertSame($test['rejected'], bin2hex(
            ParagonIE_Sodium_Compat::crypto_kem_mlkem768_dec($ciphertext, ParagonIE_Sodium_Compat::hex2bin($test['sk']))
        ));
    }
}
