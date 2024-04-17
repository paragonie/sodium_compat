<?php

class PHP84Test extends PHPUnit_Framework_TestCase
{
    /**
     * @before
     */
    public function before()
    {
        if (PHP_VERSION_ID < 80400 || !extension_loaded('sodium')) {
            $this->markTestSkipped('PHP < 8.4.0; skipping PHP 8.4 compatibility test suite.');
        }
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    public function testAegis128l()
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

    public function testAegis256()
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