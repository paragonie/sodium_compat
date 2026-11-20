<?php

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(ParagonIE_Sodium_Core_Keccak::class)]
class CoreKeccakTest extends TestCase
{
    public static function messages(): array
    {
        $cases = ['empty' => [''], 'abc' => ['abc']];
        foreach ([71, 72, 73, 135, 136, 137, 167, 168, 169, 1000] as $length) {
            $cases['binary length=' . $length] = [
                substr(str_repeat("\xff\x80\x01\0", 251), 0, $length)
            ];
        }
        return $cases;
    }

    /**
     * @dataProvider messages
     */
    #[DataProvider('messages')]
    public function testSHA3256AgainstNativeHash(string $message): void
    {
        $this->assertSame(
            hash('sha3-256', $message, true),
            ParagonIE_Sodium_Core_Keccak::sha3_256($message)
        );
    }

    /**
     * @dataProvider messages
     */
    #[DataProvider('messages')]
    public function testSHA3512AgainstNativeHash(string $message): void
    {
        $this->assertSame(
            hash('sha3-512', $message, true),
            ParagonIE_Sodium_Core_Keccak::sha3_512($message)
        );
    }

    public static function shakeVectors(): array
    {
        return [
            'shake128 empty' => [
                'shake128',
                '',
                '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93' .
                '103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75' .
                'ab916a58d974918835d25e6a435085b2badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc' .
                '1cbf1a0b3a5120ea17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdef' .
                'aee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32def58538b8d23f877'
            ],
            'shake128 abc' => [
                'shake128',
                'abc',
                '5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc844c50af32acd3f2c' .
                'dd066568706f509bc1bdde58295dae3f891a9a0fca5783789a41f8611214ce612394df286a62d1a2' .
                '252aa94db9c538956c717dc2bed4f232a0294c857c730aa16067ac1062f1201fb0d377cfb9cde4c6' .
                '3599b27f3462bba4a0ed296c801f9ff7f57302bb3076ee145f97a32ae68e76ab66c48d51675bd49a' .
                'cc29082f5647584e6aa01b3f5af057805f973ff8ecb8b226ac32ada6f01c1fcd4818cb006aa5b4cd'
            ],
            'shake256 empty' => [
                'shake256',
                '',
                '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200' .
                'cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be141e96616fb13957692cc7edd0b45ae3' .
                'dc07223c8e92937bef84bc0eab862853349ec75546f58fb7c2775c38462c5010d846c185c15111e5' .
                '95522a6bcd16cf86f3d122109e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d6' .
                '77231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5caaae314ed9083dab'
            ],
            'shake256 abc' => [
                'shake256',
                'abc',
                '483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386' .
                'c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e41385141204f329979fd3047a13c56577' .
                '24ada64d2470157b3cdc288620944d78dbcddbd912993f0913f164fb2ce95131a2d09a3e6d51cbfc' .
                '622720d7a75c6334e8a2d7ec71a7cc29cf0ea610eeff1a588290a53000faa79932becec0bd3cd0b3' .
                '3a7e5d397fed1ada9442b99903f4dcfd8559ed3950faf40fe6f3b5d710ed3b677513771af6bfe119'
            ],
        ];
    }

    /**
     * @dataProvider shakeVectors
     */
    #[DataProvider('shakeVectors')]
    public function testSHAKEKnownAnswer(string $factory, string $message, string $expected): void
    {
        $state = ParagonIE_Sodium_Core_Keccak::$factory();
        $this->assertSame($expected, bin2hex($state->absorb($message)->squeeze(200)));
    }

    /**
     * @dataProvider messages
     */
    #[DataProvider('messages')]
    public function testIncrementalSHAKE128(string $message): void
    {
        $this->checkIncremental('shake128', $message);
    }

    /**
     * @dataProvider messages
     */
    #[DataProvider('messages')]
    public function testIncrementalSHAKE256(string $message): void
    {
        $this->checkIncremental('shake256', $message);
    }

    private function checkIncremental(string $factory, string $message): void
    {
        $oneShot = ParagonIE_Sodium_Core_Keccak::$factory()->absorb($message)->squeeze(400);
        $state = ParagonIE_Sodium_Core_Keccak::$factory();
        for ($i = 0; $i < strlen($message); $i += 7) {
            $state->absorb(substr($message, $i, 7));
        }
        $this->assertSame('', $state->squeeze(0));
        $this->assertSame(
            $oneShot,
            $state->squeeze(1) . $state->squeeze(135) . $state->squeeze(0) . $state->squeeze(264)
        );
    }

    public function testAbsorbAfterSqueezeIsRejected(): void
    {
        $state = ParagonIE_Sodium_Core_Keccak::shake256();
        $state->squeeze(1);
        $this->expectException(SodiumException::class);
        $state->absorb('late input');
    }

    public function testNegativeSqueezeLengthIsRejected(): void
    {
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Core_Keccak::shake128()->squeeze(-1);
    }
}
