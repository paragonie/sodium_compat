<?php

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class SodiumCompatCryptoSecretboxTest extends KnownAnswerTestCase
{
    /**
     * @return array<int, array<int, string>>
     */
    public static function successfulTestCases(): array
    {
        return [
            [
                '2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c', // key
                '000102030405060708090a0b0c0d0e0f1011121314151617', // nonce
                'This is a test message.', // message
                '712eeb3d6945a0017e917869cce5d2e7b4b8a108d4b18a0b8fd7afee6c910f47acbadec0db1d1b', // ciphertext
            ],
        ];
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testEncrypt(string $key, string $nonce, string $message, string $ciphertext): void
    {
        $k = $this->hextobin($key);
        $n = $this->hextobin($nonce);
        $m = $message;

        $encrypted = ParagonIE_Sodium_Compat::crypto_secretbox($m, $n, $k);
        $this->assertSame(
            $ciphertext,
            ParagonIE_Sodium_Compat::bin2hex($encrypted)
        );
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testDecrypt(string $key, string $nonce, string $message, string $ciphertext): void
    {
        $k = $this->hextobin($key);
        $n = $this->hextobin($nonce);
        $c = $this->hextobin($ciphertext);

        $decrypted = ParagonIE_Sodium_Compat::crypto_secretbox_open($c, $n, $k);
        $this->assertSame($message, $decrypted);
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testDecryptFailureWrongKey(string $key, string $nonce, string $message, string $ciphertext): void
    {
        $k = $this->hextobin($key);
        $n = $this->hextobin($nonce);
        $c = $this->hextobin($ciphertext);

        // Mismatched Key
        $this->expectException(SodiumException::class);
        $wrong_key = sodium_crypto_generichash($k);
        $invalid = ParagonIE_Sodium_Compat::crypto_secretbox_open($c, $n, $wrong_key);
        var_dump($invalid);
    }


    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testDecryptFailureWrongNonce(string $key, string $nonce, string $message, string $ciphertext): void
    {
        $k = $this->hextobin($key);
        $n = $this->hextobin($nonce);
        $c = $this->hextobin($ciphertext);

        // Mismatched Nonce
        $this->expectException(SodiumException::class);
        $wrong_nonce = sodium_crypto_generichash($n, '', 24);
        $this->assertFalse(ParagonIE_Sodium_Compat::crypto_secretbox_open($c, $wrong_nonce, $k));
    }

    public function testInvalidKeyLength(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Argument 3 must be CRYPTO_SECRETBOX_KEYBYTES long.');
        ParagonIE_Sodium_Compat::crypto_secretbox(
            'message',
            str_repeat("\x00", 24),
            str_repeat("\x00", 31)
        );
    }

    public function testInvalidNonceLength(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Argument 2 must be CRYPTO_SECRETBOX_NONCEBYTES long.');
        ParagonIE_Sodium_Compat::crypto_secretbox(
            'message',
            str_repeat("\x00", 23),
            str_repeat("\x00", 32)
        );
    }

    public function testInvalidCiphertextLength(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Ciphertext must be at least CRYPTO_SECRETBOX_MACBYTES long');
        ParagonIE_Sodium_Compat::crypto_secretbox_open(
            'm',
            str_repeat("\x00", 24),
            str_repeat("\x00", 32)
        );
    }
}
