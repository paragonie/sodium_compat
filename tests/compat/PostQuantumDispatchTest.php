<?php

use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class PostQuantumDispatchTest extends TestCase
{
    private bool $previousFallback;

    /**
     * @before
     */
    #[Before]
    public function before(): void
    {
        $this->previousFallback = ParagonIE_Sodium_Compat::$disableFallbackForUnitTests;
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = false;
    }

    /**
     * @after
     */
    #[After]
    public function after(): void
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = $this->previousFallback;
    }

    public static function nonSodiumFunctions(): array
    {
        return [
            'missing function' => ['sodium_compat_pq_missing'],
            'userland function' => ['sodium_compat_pq_dispatch_probe'],
            'other native extension' => ['strlen']
        ];
    }

    /**
     * @dataProvider nonSodiumFunctions
     */
    #[DataProvider('nonSodiumFunctions')]
    public function testOnlySodiumFunctionsQualifyForDispatch(string $function): void
    {
        $this->assertFalse(PostQuantumNativeProbe::native($function));
    }

    public function testNativeSodiumDetectionRespectsForcedPHPExecution(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('ext-sodium is unavailable');
        }
        $this->assertTrue(PostQuantumNativeProbe::native('sodium_crypto_scalarmult'));
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
        $this->assertFalse(PostQuantumNativeProbe::native('sodium_crypto_scalarmult'));
    }

    /**
     * @throws SodiumException
     */
    public function testFallbackEnabledDoesNotRecurseThroughPolyfill(): void
    {
        $seed = str_repeat("\x35", 32);
        $expected = ParagonIE_Sodium_Core_XWing::seedKeypair($seed);
        $this->assertSame($expected, ParagonIE_Sodium_Compat::crypto_kem_xwing_seed_keypair($seed));
        $this->assertSame($expected, sodium_crypto_kem_xwing_seed_keypair($seed));
    }
}
