<?php

use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class KdfTest extends TestCase
{
    /**
     * @before
     */
    #[Before]
    public function before(): void
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    public function testKeygen(): void
    {
        $key = ParagonIE_Sodium_Compat::crypto_kdf_keygen();
        $this->assertSame(ParagonIE_Sodium_Compat::CRYPTO_KDF_KEYBYTES, strlen($key));
    }

    /**
     * @throws SodiumException
     */
    public function testDeriveFromKey(): void
    {
        $key = ParagonIE_Sodium_Compat::crypto_kdf_keygen();
        $context = 'test-ctx';
        while (strlen($context) < ParagonIE_Sodium_Compat::CRYPTO_KDF_CONTEXTBYTES) {
            $context .= $context;
        }
        $context = substr($context, 0, ParagonIE_Sodium_Compat::CRYPTO_KDF_CONTEXTBYTES);

        $subkey1 = ParagonIE_Sodium_Compat::crypto_kdf_derive_from_key(
            ParagonIE_Sodium_Compat::CRYPTO_KDF_BYTES_MIN,
            1,
            $context,
            $key
        );
        $this->assertSame(ParagonIE_Sodium_Compat::CRYPTO_KDF_BYTES_MIN, strlen($subkey1));

        $subkey2 = ParagonIE_Sodium_Compat::crypto_kdf_derive_from_key(
            ParagonIE_Sodium_Compat::CRYPTO_KDF_BYTES_MAX,
            2,
            $context,
            $key
        );
        $this->assertSame(ParagonIE_Sodium_Compat::CRYPTO_KDF_BYTES_MAX, strlen($subkey2));

        $subkey3 = ParagonIE_Sodium_Compat::crypto_kdf_derive_from_key(
            ParagonIE_Sodium_Compat::CRYPTO_KDF_BYTES_MAX,
            1,
            $context,
            $key
        );
        $this->assertNotSame($subkey1, $subkey3);
        $this->assertNotSame($subkey2, $subkey3);
    }

    /**
     * @throws SodiumException
     */
    public function testInvalidInputs(): void
    {
        $key = ParagonIE_Sodium_Compat::crypto_kdf_keygen();
        $context = str_repeat("\0", ParagonIE_Sodium_Compat::CRYPTO_KDF_CONTEXTBYTES);

        try {
            ParagonIE_Sodium_Compat::crypto_kdf_derive_from_key(
                ParagonIE_Sodium_Compat::CRYPTO_KDF_BYTES_MIN - 1,
                1,
                $context,
                $key
            );
            $this->fail('Subkey length too short');
        } catch (SodiumException $ex) {
            $this->assertSame('subkey cannot be smaller than SODIUM_CRYPTO_KDF_BYTES_MIN', $ex->getMessage());
        }

        try {
            ParagonIE_Sodium_Compat::crypto_kdf_derive_from_key(
                ParagonIE_Sodium_Compat::CRYPTO_KDF_BYTES_MAX + 1,
                1,
                $context,
                $key
            );
            $this->fail('Subkey length too long');
        } catch (SodiumException $ex) {
            $this->assertSame('subkey cannot be larger than SODIUM_CRYPTO_KDF_BYTES_MAX', $ex->getMessage());
        }

        try {
            ParagonIE_Sodium_Compat::crypto_kdf_derive_from_key(
                ParagonIE_Sodium_Compat::CRYPTO_KDF_BYTES_MIN,
                -1,
                $context,
                $key
            );
            $this->fail('Subkey ID cannot be negative');
        } catch (SodiumException $ex) {
            $this->assertSame('subkey_id cannot be negative', $ex->getMessage());
        }

        try {
            ParagonIE_Sodium_Compat::crypto_kdf_derive_from_key(
                ParagonIE_Sodium_Compat::CRYPTO_KDF_BYTES_MIN,
                1,
                'short',
                $key
            );
            $this->fail('Context too short');
        } catch (SodiumException $ex) {
            $this->assertSame('context should be SODIUM_CRYPTO_KDF_CONTEXTBYTES bytes', $ex->getMessage());
        }

        try {
            ParagonIE_Sodium_Compat::crypto_kdf_derive_from_key(
                ParagonIE_Sodium_Compat::CRYPTO_KDF_BYTES_MIN,
                1,
                $context,
                'short'
            );
            $this->fail('Key too short');
        } catch (SodiumException $ex) {
            $this->assertSame('key should be SODIUM_CRYPTO_KDF_KEYBYTES bytes', $ex->getMessage());
        }
    }
}
