<?php

require_once dirname(__FILE__) . '/PQVectorProvider.php';

/**
 * @covers ParagonIE_Sodium_Compat
 * @covers ParagonIE_Sodium_Core_MLKEM768
 * @covers ParagonIE_Sodium_Core_MLDSA44
 */
class PostQuantumWycheproofTest extends PHPUnit_Framework_TestCase
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
    public static function mlkemKeygenVectors()
    {
        return PQVectorProvider::wycheproof('mlkem_768_keygen_seed');
    }

    /**
     * @dataProvider mlkemKeygenVectors
     * @throws SodiumException
     */
    public function testMLKEMSeedKeypair(array $group, array $test)
    {
        $keypair = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_seed_keypair(ParagonIE_Sodium_Compat::hex2bin($test['seed']));
        $this->assertSame($test['dk'] . $test['ek'], bin2hex($keypair));
        $this->assertSame($test['ek'], bin2hex(ParagonIE_Sodium_Compat::crypto_kem_mlkem768_publickey($keypair)));
        $this->assertSame($test['dk'], bin2hex(ParagonIE_Sodium_Compat::crypto_kem_mlkem768_secretkey($keypair)));
    }

    /**
     * @throws JsonException
     */
    public static function mlkemEncapsulationVectors()
    {
        return PQVectorProvider::wycheproof('mlkem_768_encaps');
    }

    /**
     * @dataProvider mlkemEncapsulationVectors
     */
    public function testMLKEMEncapsulation(array $group, array $test)
    {
        if ($test['result'] === 'invalid') {
            if (method_exists($this, 'expectException')) {
                $this->expectException('SodiumException');
            } else {
                $this->setExpectedException('SodiumException');
            }
        }
        $result = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_enc_deterministic(
            ParagonIE_Sodium_Compat::hex2bin($test['ek']),
            ParagonIE_Sodium_Compat::hex2bin($test['m'])
        );
        $this->assertSame($test['c'], bin2hex($result[0]), 'Ciphertext');
        $this->assertSame($test['K'], bin2hex($result[1]), 'Shared secret');
    }

    /**
     * @throws JsonException
     */
    public static function noncanonicalEncapsulationKeys()
    {
        $cases = array();
        foreach (self::mlkemEncapsulationVectors() as $name => $case) {
            if ($case[1]['result'] === 'invalid') {
                $cases[$name] = $case;
            }
        }
        return $cases;
    }

    /**
     * @dataProvider noncanonicalEncapsulationKeys
     */
    public function testMLKEMRejectsNoncanonicalPublicKeyWithValidRandomness(array $group, array $test)
    {
        if (method_exists($this, 'expectException')) {
            $this->expectException('SodiumException');
        } else {
            $this->setExpectedException('SodiumException');
        }
        ParagonIE_Sodium_Compat::crypto_kem_mlkem768_enc_deterministic(
            ParagonIE_Sodium_Compat::hex2bin($test['ek']),
            str_repeat("\x42", 32)
        );
    }

    /**
     * @throws JsonException
     */
    public static function mlkemDecapsulationVectors()
    {
        return PQVectorProvider::wycheproof('mlkem_768');
    }

    /**
     * @dataProvider mlkemDecapsulationVectors
     * @throws SodiumException
     */
    public function testMLKEMDecapsulation(array $group, array $test)
    {
        if (strlen($test['seed']) !== 128) {
            if (method_exists($this, 'expectException')) {
                $this->expectException('SodiumException');
            } else {
                $this->setExpectedException('SodiumException');
            }
            ParagonIE_Sodium_Compat::crypto_kem_mlkem768_seed_keypair(ParagonIE_Sodium_Compat::hex2bin($test['seed']));
            return;
        }
        $keypair = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_seed_keypair(ParagonIE_Sodium_Compat::hex2bin($test['seed']));
        if ($test['result'] === 'invalid') {
            if (method_exists($this, 'expectException')) {
                $this->expectException('SodiumException');
            } else {
                $this->setExpectedException('SodiumException');
            }
        }
        $actual = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_dec(ParagonIE_Sodium_Compat::hex2bin($test['c']), substr($keypair, 0, 2400));
        $this->assertSame($test['K'], bin2hex($actual));
    }

    /**
     * @throws JsonException
     */
    public static function expandedDecapsulationVectors()
    {
        return PQVectorProvider::wycheproof('mlkem_768_semi_expanded_decaps');
    }

    /**
     * @dataProvider expandedDecapsulationVectors
     * @throws SodiumException
     */
    public function testMLKEMExpandedSecretKeyValidation(array $group, array $test)
    {
        if ($test['result'] === 'invalid') {
            if (method_exists($this, 'expectException')) {
                $this->expectException('SodiumException');
            } else {
                $this->setExpectedException('SodiumException');
            }
        }
        // These import-validation vectors do not specify an expected shared secret.
        $secret = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_dec(
            ParagonIE_Sodium_Compat::hex2bin($test['c']),
            ParagonIE_Sodium_Compat::hex2bin($test['dk'])
        );
        $this->assertSame(32, strlen($secret));
    }

    /**
     * @throws JsonException
     */
    public static function mldsaVerificationVectors()
    {
        return PQVectorProvider::wycheproof('mldsa_44_verify');
    }

    /**
     * @dataProvider mldsaVerificationVectors
     */
    public function testMLDSAVerification(array $group, array $test)
    {
        $context = ParagonIE_Sodium_Compat::hex2bin((isset($test['ctx']) ? $test['ctx'] : ''));
        if (strlen($test['sig']) !== 4840 || strlen($group['publicKey']) !== 2624 || strlen($context) > 255) {
            if (method_exists($this, 'expectException')) {
                $this->expectException('SodiumException');
            } else {
                $this->setExpectedException('SodiumException');
            }
        }
        $this->assertSame(
            $test['result'] === 'valid',
            ParagonIE_Sodium_Compat::crypto_sign_mldsa44_verify_detached_ctx(
                ParagonIE_Sodium_Compat::hex2bin($test['sig']),
                ParagonIE_Sodium_Compat::hex2bin($test['msg']),
                $context,
                ParagonIE_Sodium_Compat::hex2bin($group['publicKey'])
            )
        );
    }

    /**
     * @throws JsonException
     */
    public static function mldsaSeedSigningVectors()
    {
        return PQVectorProvider::wycheproof('mldsa_44_sign_seed');
    }

    /**
     * @throws JsonException
     */
    public static function mldsaExpandedSigningVectors()
    {
        return PQVectorProvider::wycheproof('mldsa_44_sign_noseed');
    }

    /**
     * @dataProvider mldsaSeedSigningVectors
     */
    public function testMLDSASeededSigning(array $group, array $test)
    {
        if (strlen($group['privateSeed']) !== 64) {
            if (method_exists($this, 'expectException')) {
                $this->expectException('SodiumException');
            } else {
                $this->setExpectedException('SodiumException');
            }
        }
        $keypair = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_seed_keypair(ParagonIE_Sodium_Compat::hex2bin($group['privateSeed']));
        $this->assertSame($group['publicKey'], bin2hex(substr($keypair, 2560)));
        $this->checkMLDSASignature($group, $test, substr($keypair, 0, 2560));
    }

    /**
     * @dataProvider mldsaExpandedSigningVectors
     * @throws SodiumException
     */
    public function testMLDSAExpandedKeySigning(array $group, array $test)
    {
        $this->checkMLDSASignature($group, $test, ParagonIE_Sodium_Compat::hex2bin($group['privateKey']));
    }

    /**
     * @throws SodiumException
     */
    private function checkMLDSASignature(array $group, array $test, $secretKey)
    {
        $message = ParagonIE_Sodium_Compat::hex2bin((isset($test['msg']) ? $test['msg'] : ''));
        $context = ParagonIE_Sodium_Compat::hex2bin((isset($test['ctx']) ? $test['ctx'] : ''));
        if ($test['result'] === 'invalid') {
            if (method_exists($this, 'expectException')) {
                $this->expectException('SodiumException');
            } else {
                $this->setExpectedException('SodiumException');
            }
            ParagonIE_Sodium_Compat::crypto_sign_mldsa44_detached_ctx($message, $context, $secretKey);
            return;
        }
        if (in_array('Internal', $test['flags'], true)) {
            $signature = ParagonIE_Sodium_Core_MLDSA44::signMu(
                ParagonIE_Sodium_Compat::hex2bin($test['mu']),
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
                ParagonIE_Sodium_Compat::hex2bin($group['publicKey'])
            ));
        }
        $this->assertSame($test['sig'], bin2hex($signature));
    }
}
