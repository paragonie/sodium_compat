<?php

use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
#[CoversClass(ParagonIE_Sodium_Core_MLKEM768::class)]
#[CoversClass(ParagonIE_Sodium_Core_MLDSA44::class)]
class PostQuantumWycheproofTest extends TestCase
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
    public static function mlkemKeygenVectors(): array
    {
        return PQVectorProvider::wycheproof('mlkem_768_keygen_seed');
    }

    /**
     * @dataProvider mlkemKeygenVectors
     * @throws SodiumException
     */
    #[DataProvider('mlkemKeygenVectors')]
    public function testMLKEMSeedKeypair(array $group, array $test): void
    {
        $keypair = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_seed_keypair(hex2bin($test['seed']));
        $this->assertSame($test['dk'] . $test['ek'], bin2hex($keypair));
        $this->assertSame($test['ek'], bin2hex(ParagonIE_Sodium_Compat::crypto_kem_mlkem768_publickey($keypair)));
        $this->assertSame($test['dk'], bin2hex(ParagonIE_Sodium_Compat::crypto_kem_mlkem768_secretkey($keypair)));
    }

    /**
     * @throws JsonException
     */
    public static function mlkemEncapsulationVectors(): array
    {
        return PQVectorProvider::wycheproof('mlkem_768_encaps');
    }

    /**
     * @dataProvider mlkemEncapsulationVectors
     */
    #[DataProvider('mlkemEncapsulationVectors')]
    public function testMLKEMEncapsulation(array $group, array $test): void
    {
        if ($test['result'] === 'invalid') {
            $this->expectException(SodiumException::class);
        }
        $result = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_enc_deterministic(
            hex2bin($test['ek']),
            hex2bin($test['m'])
        );
        $this->assertSame($test['c'], bin2hex($result[0]), 'Ciphertext');
        $this->assertSame($test['K'], bin2hex($result[1]), 'Shared secret');
    }

    /**
     * @throws JsonException
     */
    public static function noncanonicalEncapsulationKeys(): array
    {
        return array_filter(self::mlkemEncapsulationVectors(), static function (array $case): bool {
            return $case[1]['result'] === 'invalid';
        });
    }

    /**
     * @dataProvider noncanonicalEncapsulationKeys
     */
    #[DataProvider('noncanonicalEncapsulationKeys')]
    public function testMLKEMRejectsNoncanonicalPublicKeyWithValidRandomness(array $group, array $test): void
    {
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::crypto_kem_mlkem768_enc_deterministic(
            hex2bin($test['ek']),
            str_repeat("\x42", 32)
        );
    }

    /**
     * @throws JsonException
     */
    public static function mlkemDecapsulationVectors(): array
    {
        return PQVectorProvider::wycheproof('mlkem_768');
    }

    /**
     * @dataProvider mlkemDecapsulationVectors
     * @throws SodiumException
     */
    #[DataProvider('mlkemDecapsulationVectors')]
    public function testMLKEMDecapsulation(array $group, array $test): void
    {
        if (strlen($test['seed']) !== 128) {
            $this->expectException(SodiumException::class);
            ParagonIE_Sodium_Compat::crypto_kem_mlkem768_seed_keypair(hex2bin($test['seed']));
            return;
        }
        $keypair = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_seed_keypair(hex2bin($test['seed']));
        if ($test['result'] === 'invalid') {
            $this->expectException(SodiumException::class);
        }
        $actual = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_dec(hex2bin($test['c']), substr($keypair, 0, 2400));
        $this->assertSame($test['K'], bin2hex($actual));
    }

    /**
     * @throws JsonException
     */
    public static function expandedDecapsulationVectors(): array
    {
        return PQVectorProvider::wycheproof('mlkem_768_semi_expanded_decaps');
    }

    /**
     * @dataProvider expandedDecapsulationVectors
     * @throws SodiumException
     */
    #[DataProvider('expandedDecapsulationVectors')]
    public function testMLKEMExpandedSecretKeyValidation(array $group, array $test): void
    {
        if ($test['result'] === 'invalid') {
            $this->expectException(SodiumException::class);
        }
        // These import-validation vectors do not specify an expected shared secret.
        $secret = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_dec(
            hex2bin($test['c']),
            hex2bin($test['dk'])
        );
        $this->assertSame(32, strlen($secret));
    }

    /**
     * @throws JsonException
     */
    public static function mldsaVerificationVectors(): array
    {
        return PQVectorProvider::wycheproof('mldsa_44_verify');
    }

    /**
     * @dataProvider mldsaVerificationVectors
     */
    #[DataProvider('mldsaVerificationVectors')]
    public function testMLDSAVerification(array $group, array $test): void
    {
        $context = hex2bin($test['ctx'] ?? '');
        if (strlen($test['sig']) !== 4840 || strlen($group['publicKey']) !== 2624 || strlen($context) > 255) {
            $this->expectException(SodiumException::class);
        }
        $this->assertSame(
            $test['result'] === 'valid',
            ParagonIE_Sodium_Compat::crypto_sign_mldsa44_verify_detached_ctx(
                hex2bin($test['sig']),
                hex2bin($test['msg']),
                $context,
                hex2bin($group['publicKey'])
            )
        );
    }

    /**
     * @throws JsonException
     */
    public static function mldsaSeedSigningVectors(): array
    {
        return PQVectorProvider::wycheproof('mldsa_44_sign_seed');
    }

    /**
     * @throws JsonException
     */
    public static function mldsaExpandedSigningVectors(): array
    {
        return PQVectorProvider::wycheproof('mldsa_44_sign_noseed');
    }

    /**
     * @dataProvider mldsaSeedSigningVectors
     */
    #[DataProvider('mldsaSeedSigningVectors')]
    public function testMLDSASeededSigning(array $group, array $test): void
    {
        if (strlen($group['privateSeed']) !== 64) {
            $this->expectException(SodiumException::class);
        }
        $keypair = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_seed_keypair(hex2bin($group['privateSeed']));
        $this->assertSame($group['publicKey'], bin2hex(substr($keypair, 2560)));
        $this->checkMLDSASignature($group, $test, substr($keypair, 0, 2560));
    }

    /**
     * @dataProvider mldsaExpandedSigningVectors
     * @throws SodiumException
     */
    #[DataProvider('mldsaExpandedSigningVectors')]
    public function testMLDSAExpandedKeySigning(array $group, array $test): void
    {
        $this->checkMLDSASignature($group, $test, hex2bin($group['privateKey']));
    }

    /**
     * @throws SodiumException
     */
    private function checkMLDSASignature(array $group, array $test, string $secretKey): void
    {
        $message = hex2bin($test['msg'] ?? '');
        $context = hex2bin($test['ctx'] ?? '');
        if ($test['result'] === 'invalid') {
            $this->expectException(SodiumException::class);
            ParagonIE_Sodium_Compat::crypto_sign_mldsa44_detached_ctx($message, $context, $secretKey);
            return;
        }
        if (in_array('Internal', $test['flags'], true)) {
            $signature = ParagonIE_Sodium_Core_MLDSA44::signMu(
                hex2bin($test['mu']),
                $secretKey,
                str_repeat("\0", 32)
            );
        } else {
            $signature = ParagonIE_Sodium_Core_MLDSA44::sign(
                $message,
                $secretKey,
                $context,
                str_repeat("\0", 32)
            );
            $this->assertTrue(ParagonIE_Sodium_Compat::crypto_sign_mldsa44_verify_detached_ctx(
                $signature,
                $message,
                $context,
                hex2bin($group['publicKey'])
            ));
        }
        $this->assertSame($test['sig'], bin2hex($signature));
    }
}
