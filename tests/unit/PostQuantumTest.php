<?php

/**
 * @covers ParagonIE_Sodium_Compat
 */
class PostQuantumTest extends PHPUnit_Framework_TestCase
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

    public static function constants()
    {
        $cases = array();
        foreach (array(
            'KEM_MLKEM768' => array(1184, 2400, 64, 3584),
            'KEM_XWING' => array(1216, 32, 32, 1248),
            'KEM' => array(1216, 32, 32, 1248),
            'SIGN_MLDSA44' => array(1312, 2560, 32, 3872)
        ) as $algorithm => $sizes) {
            foreach (array('PUBLICKEYBYTES', 'SECRETKEYBYTES', 'SEEDBYTES', 'KEYPAIRBYTES') as $i => $suffix) {
                $cases[$algorithm . '_' . $suffix] = array('CRYPTO_' . $algorithm . '_' . $suffix, $sizes[$i]);
            }
        }
        foreach (array(
            'KEM_MLKEM768_CIPHERTEXTBYTES' => 1088,
            'KEM_XWING_CIPHERTEXTBYTES' => 1120,
            'KEM_CIPHERTEXTBYTES' => 1120,
            'KEM_MLKEM768_SHAREDSECRETBYTES' => 32,
            'KEM_XWING_SHAREDSECRETBYTES' => 32,
            'KEM_SHAREDSECRETBYTES' => 32,
            'KEM_PRIMITIVE' => 'xwing',
            'SIGN_MLDSA44_BYTES' => 2420,
            'SIGN_MLDSA44_CONTEXTBYTES_MAX' => 255,
            'SIGN_MLDSA44_MESSAGEBYTES_MAX' => PHP_INT_MAX - 2420
        ) as $suffix => $expected) {
            $cases[$suffix] = array('CRYPTO_' . $suffix, $expected);
        }
        return $cases;
    }

    /**
     * @dataProvider constants
     */
    public function testPublicConstants($name, $expected)
    {
        $this->assertSame($expected, constant('ParagonIE_Sodium_Compat::' . $name));
        if (PHP_VERSION_ID >= 50300) {
            $this->assertSame($expected, constant('ParagonIE\\Sodium\\Compat::' . $name));
        }
        $this->assertSame($expected, constant('SODIUM_' . $name));
    }

    /**
     * @throws SodiumException
     */
    public function testNamespacedApi()
    {
        if (PHP_VERSION_ID < 50300) {
            $this->markTestSkipped('Namespaces require PHP 5.3');
        }
        $seed = str_repeat("\x42", 32);
        $this->assertSame(
            ParagonIE_Sodium_Compat::crypto_kem_xwing_seed_keypair($seed),
            call_user_func(array('ParagonIE\\Sodium\\Compat', 'crypto_kem_xwing_seed_keypair'), $seed)
        );
        $this->assertSame(
            ParagonIE_Sodium_Compat::crypto_sign_mldsa44_seed_keypair($seed),
            call_user_func(array('ParagonIE\\Sodium\\Compat', 'crypto_sign_mldsa44_seed_keypair'), $seed)
        );
        $keypair = call_user_func(array('ParagonIE\\Sodium\\Compat', 'crypto_kem_xwing_keypair'));
        $secret = call_user_func(array('ParagonIE\\Sodium\\Compat', 'crypto_kem_xwing_secretkey'), $keypair);
        $public = call_user_func(array('ParagonIE\\Sodium\\Compat', 'crypto_kem_xwing_publickey'), $keypair);
        $result = call_user_func(array('ParagonIE\\Sodium\\Compat', 'crypto_kem_xwing_enc'), $public);
        $this->assertSame($result[1], call_user_func(array('ParagonIE\\Sodium\\Compat', 'crypto_kem_xwing_dec'), $result[0], $secret));
        $this->assertSame(
            ParagonIE_Sodium_Compat::crypto_kem_mlkem768_seed_keypair($seed . $seed),
            call_user_func(array('ParagonIE\\Sodium\\Compat', 'crypto_kem_mlkem768_seed_keypair'), $seed . $seed)
        );
        $keypair = call_user_func(array('ParagonIE\\Sodium\\Compat', 'crypto_sign_mldsa44_keypair'));
        $secret = call_user_func(array('ParagonIE\\Sodium\\Compat', 'crypto_sign_mldsa44_secretkey'), $keypair);
        $public = call_user_func(array('ParagonIE\\Sodium\\Compat', 'crypto_sign_mldsa44_publickey'), $keypair);
        $signature = call_user_func(array('ParagonIE\\Sodium\\Compat', 'crypto_sign_mldsa44_detached_ctx'), 'message', 'context', $secret);
        $this->assertTrue(
            call_user_func(array('ParagonIE\\Sodium\\Compat', 'crypto_sign_mldsa44_verify_detached_ctx'), $signature, 'message', 'context', $public)
        );
        $this->assertFalse(
            call_user_func(array('ParagonIE\\Sodium\\Compat', 'crypto_sign_mldsa44_verify_detached_ctx'), $signature, 'other message', 'context', $public)
        );
    }

    /**
     * @throws SodiumException
     */
    public function testSecretArgumentsAreRedacted()
    {
        if (!class_exists('SensitiveParameterValue')) {
            $this->markTestSkipped('Runtime parameter redaction requires PHP 8.2');
        }
        $previous = ini_get('zend.exception_ignore_args');
        ini_set('zend.exception_ignore_args', '0');
        $keypair = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_seed_keypair(str_repeat("s", 64));
        $malformed = substr($keypair, 0, 2400);
        $malformed[0] = "\xff";
        $malformed[1] = ($malformed[1] & "\xf0") | "\x0f";
        try {
            foreach (array('private-key-marker', $malformed) as $secret) {
                $thrown = false;
                try {
                    ParagonIE_Sodium_Compat::crypto_kem_mlkem768_dec(str_repeat("\0", 1088), $secret);
                } catch (SodiumException $ex) {
                    $thrown = true;
                    foreach ($ex->getTrace() as $frame) {
                        if (!isset($frame['class']) || strncmp($frame['class'], 'ParagonIE_Sodium_', 17) !== 0) {
                            continue;
                        }
                        foreach ((isset($frame['args']) ? $frame['args'] : array()) as $argument) {
                            $this->assertNotSame($secret, $argument);
                            $this->assertNotSame(substr($secret, 0, 384), $argument);
                        }
                    }
                }
                $this->assertTrue($thrown);
            }
        } catch (Exception $ex) {
            ini_set('zend.exception_ignore_args', $previous);
            throw $ex;
        }
        ini_set('zend.exception_ignore_args', $previous);
    }
}
