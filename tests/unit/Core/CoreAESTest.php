<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(ParagonIE_Sodium_Core_AES::class)]
class CoreAESTest extends TestCase
{
    /**
     * @dataProvider provideKeyAndMessage
     */
    #[DataProvider("provideKeyAndMessage")]
    public function testEncryptDecryptECB(string $key, string $message): void
    {
        $ciphertext = ParagonIE_Sodium_Core_AES::encryptBlockECB($message, $key);
        $decrypted = ParagonIE_Sodium_Core_AES::decryptBlockECB($ciphertext, $key);

        $this->assertSame(16, strlen($ciphertext));
        $this->assertSame($message, $decrypted);
    }

    /**
     * @throws Exception
     */
    public static function provideKeyAndMessage(): array
    {
        return array(
            array(random_bytes(16), random_bytes(16)),
            array(random_bytes(24), random_bytes(16)),
            array(random_bytes(32), random_bytes(16)),
        );
    }

    /**
     * @dataProvider provideNistEcbVectors
     */
    #[DataProvider("provideNistEcbVectors")]
    public function testNistEcbVectors(string $key, string $plaintext, string $ciphertext): void
    {
        $encrypted = ParagonIE_Sodium_Core_AES::encryptBlockECB(
            ParagonIE_Sodium_Core_Util::hex2bin($plaintext),
            ParagonIE_Sodium_Core_Util::hex2bin($key)
        );
        $this->assertSame(
            $ciphertext,
            ParagonIE_Sodium_Core_Util::bin2hex($encrypted)
        );
    }

    public static function provideNistEcbVectors(): array
    {
        // Test vectors from NIST SP 800-38A, Appendix F
        return [
            // F.1.1, AES-128
            [
                '2b7e151628aed2a6abf7158809cf4f3c',
                '6bc1bee22e409f96e93d7e117393172a',
                '3ad77bb40d7a3660a89ecaf32466ef97'
            ],
            // F.1.5, AES-192
            [
                '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
                '6bc1bee22e409f96e93d7e117393172a',
                'bd334f1d6e45f25ff712a214571fa5cc'
            ],
            // F.1.9, AES-256
            [
                '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
                '6bc1bee22e409f96e93d7e117393172a',
                'f3eed1bdb5d2a03c064b5a7e3db181f8'
            ]
        ];
    }

    /**
     * @throws Exception
     */
    public function testAesRound(): void
    {
        $x = random_bytes(16);
        $y = random_bytes(16);

        $result = ParagonIE_Sodium_Core_AES::aesRound($x, $y);
        $this->assertIsString($result);
        $this->assertSame(16, strlen($result));
    }

    /**
     * @throws Exception
     */
    public function testDoubleRound(): void
    {
        $b0 = random_bytes(16);
        $rk0 = random_bytes(16);
        $b1 = random_bytes(16);
        $rk1 = random_bytes(16);

        $result = ParagonIE_Sodium_Core_AES::doubleRound($b0, $rk0, $b1, $rk1);
        $this->assertIsArray($result);
        $this->assertCount(2, $result);
        $this->assertIsString($result[0]);
        $this->assertSame(16, strlen($result[0]));
        $this->assertIsString($result[1]);
        $this->assertSame(16, strlen($result[1]));
    }
}
