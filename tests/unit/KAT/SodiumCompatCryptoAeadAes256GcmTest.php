<?php

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class SodiumCompatCryptoAeadAes256GcmTest extends KnownAnswerTestCase
{
    /**
     * @return array<int, array<int, string>>
     */
    public static function successfulTestCases(): array
    {
        return [
            [
                '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e', // key
                '42831ec2217774244b7221b7', // nonce
                'feedfacedeadbeeffeedfacedeadbeefabaddad2', // ad
                'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39', // plaintext
                'dfa84dcd0a92ce7ef65f10dab6a6a5b99960d0860a12dce5c77785adeee8460c1160eff301af54d4391c3ed6816efda3c5c02e5d8de4a100e8f4bf24f026160d48350034b7f81c1eb5d4254a', // ciphertext
            ],
        ];
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testEncrypt(string $key, string $nonce, string $ad, string $plaintext, string $ciphertext): void
    {
        if (!ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_is_available()) {
            $this->markTestSkipped('AES-256-GCM not available');
        }
        $k = $this->hextobin($key);
        $n = $this->hextobin($nonce);
        $a = $this->hextobin($ad);
        $p = $this->hextobin($plaintext);

        $calculatedCiphertext = ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_encrypt($p, $a, $n, $k);
        $this->assertSame(
            $ciphertext,
            ParagonIE_Sodium_Compat::bin2hex($calculatedCiphertext)
        );
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testDecrypt(string $key, string $nonce, string $ad, string $plaintext, string $ciphertext): void
    {
        if (!ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_is_available()) {
            $this->markTestSkipped('AES-256-GCM not available');
        }
        $k = $this->hextobin($key);
        $n = $this->hextobin($nonce);
        $a = $this->hextobin($ad);
        $c = $this->hextobin($ciphertext);

        $calculatedPlaintext = ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_decrypt($c, $a, $n, $k);
        $this->assertSame(
            $plaintext,
            ParagonIE_Sodium_Compat::bin2hex($calculatedPlaintext)
        );
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testDecryptFailures(string $key, string $nonce, string $ad, string $plaintext, string $ciphertext): void
    {
        if (!ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_is_available()) {
            $this->markTestSkipped('AES-256-GCM not available');
        }
        $k = $this->hextobin($key);
        $n = $this->hextobin($nonce);
        $a = $this->hextobin($ad);
        $c = $this->hextobin($ciphertext);

        // Mismatched AD
        $decrypted = ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_decrypt($c, $c, $n, $k);
        $this->assertFalse($decrypted);

        // Mismatched Key
        $decrypted = ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_decrypt($c, $a, $n, str_repeat("\x00", 32));
        $this->assertFalse($decrypted);

        // Mismatched Nonce
        $decrypted = ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_decrypt($c, $a, str_repeat("\x00", 12), $k);
        $this->assertFalse($decrypted);
    }

    public function testInvalidKeyLengths(): void
    {
        if (!ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_is_available()) {
            $this->markTestSkipped('AES-256-GCM not available');
        }
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Key must be CRYPTO_AEAD_AES256GCM_KEYBYTES long');
        ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_encrypt(
            'plaintext',
            'ad',
            str_repeat("\x00", 12),
            str_repeat("\x00", 31)
        );
    }

    public function testInvalidNonceLengths(): void
    {
        if (!ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_is_available()) {
            $this->markTestSkipped('AES-256-GCM not available');
        }
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Nonce must be CRYPTO_AEAD_AES256GCM_NPUBBYTES long');
        ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_encrypt(
            'plaintext',
            'ad',
            str_repeat("\x00", 11),
            str_repeat("\x00", 32)
        );
    }

    public function testEmptyInputsEncrypt(): void
    {
        if (!ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_is_available()) {
            $this->markTestSkipped('AES-256-GCM not available');
        }
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_encrypt('', '', '', '');
    }

    public function testEmptyInputsDecrypt(): void
    {
        if (!ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_is_available()) {
            $this->markTestSkipped('AES-256-GCM not available');
        }
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_decrypt('', '', '', '');
    }
}