<?php

require_once dirname(__FILE__) . '/PostQuantumNativeProbe.php';

class PostQuantumDispatchTest extends PHPUnit_Framework_TestCase
{
    private $previousFallback;

    /**
     * @before
     */
    public function before()
    {
        $this->previousFallback = ParagonIE_Sodium_Compat::$disableFallbackForUnitTests;
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = false;
    }

    /**
     * @after
     */
    public function after()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = $this->previousFallback;
    }

    public static function nonSodiumFunctions()
    {
        return array(
            'missing function' => array('sodium_compat_pq_missing'),
            'userland function' => array('sodium_compat_pq_dispatch_probe'),
            'other native extension' => array('strlen')
        );
    }

    /**
     * @dataProvider nonSodiumFunctions
     */
    public function testOnlySodiumFunctionsQualifyForDispatch($function)
    {
        $this->assertFalse(PostQuantumNativeProbe::native($function));
    }

    public function testNativeSodiumDetectionRespectsForcedPHPExecution()
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
    public function testFallbackEnabledDoesNotRecurseThroughPolyfill()
    {
        $seed = str_repeat("\x35", 32);
        $expected = ParagonIE_Sodium_Core_XWing::seedKeypair($seed);
        $this->assertSame($expected, ParagonIE_Sodium_Compat::crypto_kem_xwing_seed_keypair($seed));
        $this->assertSame($expected, sodium_crypto_kem_xwing_seed_keypair($seed));
    }
}
