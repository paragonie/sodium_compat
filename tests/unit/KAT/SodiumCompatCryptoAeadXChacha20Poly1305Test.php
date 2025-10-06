<?php

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class SodiumCompatCryptoAeadXChacha20Poly1305Test extends KnownAnswerTestCase
{
    /**
     * @return array<int, array<int, string>>
     */
    public static function successfulTestCases(): array
    {
        // From libsodium
        return [
            [
                '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f', // key
                '404142434445464748494a4b4c4d4e4f5051525354555657', // nonce
                '50515253c0c1c2c3c4c5c6c7', // ad
                '4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e', // plaintext
                'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49', // ciphertext with tag
            ],
        ];
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testEncrypt(string $key, string $nonce, string $ad, string $plaintext, string $ciphertext): void
    {
        $k = $this->hextobin($key);
        $n = $this->hextobin($nonce);
        $a = $this->hextobin($ad);
        $p = $this->hextobin($plaintext);

        $calculatedCiphertext = ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_encrypt($p, $a, $n, $k);
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
        $k = $this->hextobin($key);
        $n = $this->hextobin($nonce);
        $a = $this->hextobin($ad);
        $c = $this->hextobin($ciphertext);

        $calculatedPlaintext = ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_decrypt($c, $a, $n, $k);
        $this->assertSame(
            $plaintext,
            ParagonIE_Sodium_Compat::bin2hex($calculatedPlaintext)
        );
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testDecryptFailureWrongAAD(string $key, string $nonce, string $ad, string $plaintext, string $ciphertext): void
    {
        $k = $this->hextobin($key);
        $n = $this->hextobin($nonce);
        $a = $this->hextobin($ad);
        $c = $this->hextobin($ciphertext);

        // Mismatched AD
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_decrypt($c, $c, $n, $k);
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testDecryptFailureWrongKey(string $key, string $nonce, string $ad, string $plaintext, string $ciphertext): void
    {
        $k = $this->hextobin($key);
        $n = $this->hextobin($nonce);
        $a = $this->hextobin($ad);
        $c = $this->hextobin($ciphertext);

        // Mismatched Key
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_decrypt($c, $a, $n, str_repeat("\x00", 32));
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testDecryptFailureWrongNonce(string $key, string $nonce, string $ad, string $plaintext, string $ciphertext): void
    {
        $k = $this->hextobin($key);
        $n = $this->hextobin($nonce);
        $a = $this->hextobin($ad);
        $c = $this->hextobin($ciphertext);

        // Mismatched Nonce
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_decrypt($c, $a, str_repeat("\x00", 24), $k);
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testDecryptFailureTamperedCiphertext(string $key, string $nonce, string $ad, string $plaintext, string $ciphertext): void
    {
        $k = $this->hextobin($key);
        $n = $this->hextobin($nonce);
        $a = $this->hextobin($ad);
        $c = $this->hextobin($ciphertext);

        // Tamper with the ciphertext
        $tampered_c = $c;
        $last_byte_index = ParagonIE_Sodium_Core_Util::strlen($tampered_c) - 1;
        if ($last_byte_index < 0) {
            $this->markTestSkipped('Ciphertext is empty');
        }
        $tampered_c[$last_byte_index] = \chr(\ord($tampered_c[$last_byte_index]) ^ 0xff);

        // Mismatched Ciphertext/Tag
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_decrypt($tampered_c, $a, $n, $k);
    }

    public function testInvalidKeyLengths(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Key must be CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES long');
        ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_encrypt(
            'plaintext',
            'ad',
            str_repeat("\x00", 24),
            str_repeat("\x00", 31)
        );
    }

    public function testInvalidNonceLengths(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Nonce must be CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES long');
        ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_encrypt(
            'plaintext',
            'ad',
            str_repeat("\x00", 23),
            str_repeat("\x00", 32)
        );
    }

    public function testInvalidCiphertextLength(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Message must be at least CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES long');
        ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_decrypt(
            '',
            'ad',
            str_repeat("\x00", 24),
            str_repeat("\x00", 32)
        );
    }

    public function testEmptyInputsEncrypt(): void
    {
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_encrypt('', '', '', '');
    }

    public function testEmptyInputsDecrypt(): void
    {
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_decrypt('', '', '', '');
    }
}
