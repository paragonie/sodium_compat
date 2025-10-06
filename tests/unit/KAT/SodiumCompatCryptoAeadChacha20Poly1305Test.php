<?php

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class SodiumCompatCryptoAeadChacha20Poly1305Test extends KnownAnswerTestCase
{
    /**
     * @return array<int, array<int, string>>
     */
    public static function successfulTestCases(): array
    {
        // From RFC 7539
        return [
            [
                '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f', // key
                '070000004041424344454647', // nonce (and counter)
                '50515253c0c1c2c3c4c5c6c7', // ad
                '4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e', // plaintext
                'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691', // ciphertext with tag
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

        $calculatedCiphertext = ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_encrypt($p, $a, $n, $k);
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

        $calculatedPlaintext = ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt($c, $a, $n, $k);
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
        ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt($c, $c, $n, $k);
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
        $wrong_key = ParagonIE_Sodium_Compat::crypto_generichash($k);

        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt($c, $a, $n, $wrong_key);
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
        $wrong_nonce = ParagonIE_Sodium_Compat::crypto_generichash($n, '', 24);
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt($c, $a, $wrong_nonce, $k);
    }

    public function testInvalidKeyLengths(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Key must be CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES long');
        ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_encrypt(
            'plaintext',
            'ad',
            str_repeat("\x00", 12),
            str_repeat("\x00", 31)
        );
    }

    public function testInvalidNonceLengths(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Nonce must be CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES long');
        ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_encrypt(
            'plaintext',
            'ad',
            str_repeat("\x00", 11),
            str_repeat("\x00", 32)
        );
    }

    public function testInvalidCiphertextLength(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Message must be at least CRYPTO_AEAD_CHACHA20POLY1305_ABYTES long');
        ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt(
            '',
            'ad',
            str_repeat("\x00", 12),
            str_repeat("\x00", 32)
        );
    }

    public function testEmptyInputsEncrypt(): void
    {
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_encrypt('', '', '', '');
    }

    public function testEmptyInputsDecrypt(): void
    {
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_decrypt('', '', '', '');
    }
}
