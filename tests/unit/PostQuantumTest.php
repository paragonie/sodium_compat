<?php
declare(strict_types=1);

use ParagonIE\Sodium\Compat as NamespacedCompat;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class PostQuantumTest extends TestCase
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

    public static function constants(): array
    {
        $cases = [];
        foreach ([
            'KEM_MLKEM768' => [1184, 2400, 64, 3584],
            'KEM_XWING' => [1216, 32, 32, 1248],
            'KEM' => [1216, 32, 32, 1248],
            'SIGN_MLDSA44' => [1312, 2560, 32, 3872]
        ] as $algorithm => $sizes) {
            foreach (['PUBLICKEYBYTES', 'SECRETKEYBYTES', 'SEEDBYTES', 'KEYPAIRBYTES'] as $i => $suffix) {
                $cases[$algorithm . '_' . $suffix] = ['CRYPTO_' . $algorithm . '_' . $suffix, $sizes[$i]];
            }
        }
        foreach ([
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
        ] as $suffix => $expected) {
            $cases[$suffix] = ['CRYPTO_' . $suffix, $expected];
        }
        return $cases;
    }

    /**
     * @dataProvider constants
     */
    #[DataProvider('constants')]
    public function testPublicConstants(string $name, int|string $expected): void
    {
        $this->assertSame($expected, constant('ParagonIE_Sodium_Compat::' . $name));
        $this->assertSame($expected, constant('ParagonIE\\Sodium\\Compat::' . $name));
        $this->assertSame($expected, constant('SODIUM_' . $name));
    }

    /**
     * @throws SodiumException
     */
    public function testNamespacedApi(): void
    {
        $seed = str_repeat("\x42", 32);
        $this->assertSame(
            ParagonIE_Sodium_Compat::crypto_kem_xwing_seed_keypair($seed),
            NamespacedCompat::crypto_kem_xwing_seed_keypair($seed)
        );
        $this->assertSame(
            ParagonIE_Sodium_Compat::crypto_sign_mldsa44_seed_keypair($seed),
            NamespacedCompat::crypto_sign_mldsa44_seed_keypair($seed)
        );
        $keypair = NamespacedCompat::crypto_kem_xwing_keypair();
        $secret = NamespacedCompat::crypto_kem_xwing_secretkey($keypair);
        $public = NamespacedCompat::crypto_kem_xwing_publickey($keypair);
        $result = NamespacedCompat::crypto_kem_xwing_enc($public);
        $this->assertSame($result[1], NamespacedCompat::crypto_kem_xwing_dec($result[0], $secret));
        $this->assertSame(
            ParagonIE_Sodium_Compat::crypto_kem_mlkem768_seed_keypair($seed . $seed),
            NamespacedCompat::crypto_kem_mlkem768_seed_keypair($seed . $seed)
        );
        $keypair = NamespacedCompat::crypto_sign_mldsa44_keypair();
        $secret = NamespacedCompat::crypto_sign_mldsa44_secretkey($keypair);
        $public = NamespacedCompat::crypto_sign_mldsa44_publickey($keypair);
        $signature = NamespacedCompat::crypto_sign_mldsa44_detached_ctx('message', 'context', $secret);
        $this->assertTrue(
            NamespacedCompat::crypto_sign_mldsa44_verify_detached_ctx($signature, 'message', 'context', $public)
        );
        $this->assertFalse(
            NamespacedCompat::crypto_sign_mldsa44_verify_detached_ctx($signature, 'other message', 'context', $public)
        );
    }

    /**
     * @throws SodiumException
     */
    public function testSecretArgumentsAreRedacted(): void
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
            foreach (['private-key-marker', $malformed] as $secret) {
                $thrown = false;
                try {
                    ParagonIE_Sodium_Compat::crypto_kem_mlkem768_dec(str_repeat("\0", 1088), $secret);
                } catch (SodiumException $ex) {
                    $thrown = true;
                    foreach ($ex->getTrace() as $frame) {
                        if (!isset($frame['class']) || !str_starts_with($frame['class'], 'ParagonIE_Sodium_')) {
                            continue;
                        }
                        foreach ($frame['args'] ?? [] as $argument) {
                            $this->assertNotSame($secret, $argument);
                            $this->assertNotSame(substr($secret, 0, 384), $argument);
                        }
                    }
                }
                $this->assertTrue($thrown);
            }
        } finally {
            ini_set('zend.exception_ignore_args', $previous);
        }
    }
}
