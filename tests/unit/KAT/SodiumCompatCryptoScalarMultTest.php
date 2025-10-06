<?php

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class SodiumCompatCryptoScalarMultTest extends KnownAnswerTestCase
{
    /**
     * @return array<int, array<int, string>>
     */
    public static function successfulTestCases(): array
    {
        // From libsodium tests
        return [
            [
                'e895671946781b37b14a82b485c6742568a989ef36110f63248c1873dc8930e4', // sk
                'b15891e8428a2a0755913a4833250392c68a410321a50a12e4a423489874a210', // pk
                '64a2b2a7ff14281d50b466d014c72dfa150244b5b6f7121bb31196d93e67ba6b'  // shared secret
            ],
        ];
    }

    /**
     * @dataProvider successfulTestCases
     */
    #[DataProvider('successfulTestCases')]
    public function testCryptoScalarMult(string $sk, string $pk, string $expected): void
    {
        $s = $this->hextobin($sk);
        $p = $this->hextobin($pk);

        $q = ParagonIE_Sodium_Compat::crypto_scalarmult($s, $p);
        $this->assertSame(
            $expected,
            ParagonIE_Sodium_Compat::bin2hex($q)
        );
    }

    public function testCryptoScalarMultBase(): void
    {
        $sk = ParagonIE_Sodium_Compat::crypto_box_secretkey(
            ParagonIE_Sodium_Compat::crypto_box_keypair()
        );
        $pk_expected = ParagonIE_Sodium_Compat::crypto_box_publickey_from_secretkey($sk);

        $pk_actual = ParagonIE_Sodium_Compat::crypto_scalarmult_base($sk);
        $this->assertSame(
            ParagonIE_Sodium_Compat::bin2hex($pk_expected),
            ParagonIE_Sodium_Compat::bin2hex($pk_actual)
        );
    }
}
