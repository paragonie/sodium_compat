<?php

use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\TestCase;

class PHP84Test extends TestCase
{
    /**
     * @before
     */
    #[Before]
    public function before(): void
    {
        if (PHP_VERSION_ID < 80400 || !extension_loaded('sodium')) {
            $this->markTestSkipped('PHP < 8.4.0; skipping PHP 8.4 compatibility test suite.');
        }
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    public function testAegis128l(): void
    {
        $msg = ParagonIE_Sodium_Compat::randombytes_buf(ParagonIE_Sodium_Compat::randombytes_uniform(999) + 1);
        $nonce = ParagonIE_Sodium_Compat::randombytes_buf(ParagonIE_Sodium_Compat::CRYPTO_AEAD_AEGIS128L_NPUBBYTES);
        $ad = ParagonIE_Sodium_Compat::randombytes_buf(ParagonIE_Sodium_Compat::randombytes_uniform(999) + 1);
        $key = ParagonIE_Sodium_Compat::crypto_aead_aegis128l_keygen();
        $ciphertext = ParagonIE_Sodium_Compat::crypto_aead_aegis128l_encrypt($msg, $ad, $nonce, $key);
        $c2 = sodium_crypto_aead_aegis128l_encrypt($msg, $ad, $nonce, $key);
        $this->assertSame($ciphertext, $c2);
        $msg2 = ParagonIE_Sodium_Compat::crypto_aead_aegis128l_decrypt($ciphertext, $ad, $nonce, $key);
        $msg2b = sodium_crypto_aead_aegis128l_decrypt($c2, $ad, $nonce, $key);
        $this->assertSame($msg, $msg2);
        $this->assertSame($msg, $msg2b);
    }

    public function testAegis256(): void
    {
        $msg = ParagonIE_Sodium_Compat::randombytes_buf(ParagonIE_Sodium_Compat::randombytes_uniform(999) + 1);
        $nonce = ParagonIE_Sodium_Compat::randombytes_buf(ParagonIE_Sodium_Compat::CRYPTO_AEAD_AEGIS256_NPUBBYTES);
        $ad = ParagonIE_Sodium_Compat::randombytes_buf(ParagonIE_Sodium_Compat::randombytes_uniform(999) + 1);
        $key = ParagonIE_Sodium_Compat::crypto_aead_aegis256_keygen();
        $ciphertext = ParagonIE_Sodium_Compat::crypto_aead_aegis256_encrypt($msg, $ad, $nonce, $key);
        $c2 = sodium_crypto_aead_aegis256_encrypt($msg, $ad, $nonce, $key);
        $this->assertSame($ciphertext, $c2);
        $msg2 = ParagonIE_Sodium_Compat::crypto_aead_aegis256_decrypt($ciphertext, $ad, $nonce, $key);
        $msg2b = sodium_crypto_aead_aegis256_decrypt($c2, $ad, $nonce, $key);
        $this->assertSame($msg, $msg2);
        $this->assertSame($msg, $msg2b);
    }
}