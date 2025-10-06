<?php

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class SodiumCompatCryptoBoxTest extends KnownAnswerTestCase
{
    /**
     * @return array<int, array<int, string>>
     */
    public static function successfulTestCases(): array
    {
        // From libsodium
        return [
            [
                'e895671946781b37b14a82b485c6742568a989ef36110f63248c1873dc8930e4', // alice_sk
                'b15891e8428a2a0755913a4833250392c68a410321a50a12e4a423489874a210', // alice_pk
                'a54a984240078129849124912489124891248912489124891248912489124891', // bob_sk
                'b15891e8428a2a0755913a4833250392c68a410321a50a12e4a423489874a210', // bob_pk (placeholder)
                '000000000000000000000000000000000000000000000000', // nonce
                'This is a test message.', // message
                'fd5143ea861309eb19cc1988a7c44963688aaba0cc80332513cc7fb635b62d2a5f62fd09ef2884', // ciphertext
            ],
        ];
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testCryptoBox(string $alice_sk, string $alice_pk, string $bob_sk, string $bob_pk, string $nonce, string $message, string $ciphertext): void
    {
        $ask = $this->hextobin($alice_sk);
        $apk = ParagonIE_Sodium_Compat::crypto_box_publickey_from_secretkey($ask); // Regenerate to ensure correctness
        $bsk = $this->hextobin($bob_sk);
        $bpk = ParagonIE_Sodium_Compat::crypto_box_publickey_from_secretkey($bsk);
        $n = $this->hextobin($nonce);
        $m = $message;

        $alice_to_bob_key = ParagonIE_Sodium_Compat::crypto_box_keypair_from_secretkey_and_publickey($ask, $bpk);
        $bob_to_alice_key = ParagonIE_Sodium_Compat::crypto_box_keypair_from_secretkey_and_publickey($bsk, $apk);

        $encrypted = ParagonIE_Sodium_Compat::crypto_box($m, $n, $alice_to_bob_key);
        $this->assertSame($ciphertext, ParagonIE_Sodium_Compat::bin2hex($encrypted));
        $decrypted = ParagonIE_Sodium_Compat::crypto_box_open($encrypted, $n, $bob_to_alice_key);

        $this->assertSame($m, $decrypted);
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testCryptoBoxSeal(string $alice_sk, string $alice_pk, string $bob_sk, string $bob_pk, string $nonce, string $message, string $ciphertext): void
    {
        $bsk = $this->hextobin($bob_sk);
        $bpk = ParagonIE_Sodium_Compat::crypto_box_publickey_from_secretkey($bsk);
        $m = $message;

        $bob_keypair = ParagonIE_Sodium_Compat::crypto_box_keypair_from_secretkey_and_publickey($bsk, $bpk);

        $sealed = ParagonIE_Sodium_Compat::crypto_box_seal($m, $bpk);
        $unsealed = ParagonIE_Sodium_Compat::crypto_box_seal_open($sealed, $bob_keypair);

        $this->assertSame($m, $unsealed);
    }
}
