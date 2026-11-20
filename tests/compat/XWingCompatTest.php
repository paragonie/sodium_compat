<?php

use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class XWingCompatTest extends TestCase
{
    private bool $previousFallback;

    /**
     * @throws SodiumException
     */
    public function testGenericKEMAliasesUseXWing(): void
    {
        $seed = str_repeat("\x23", 32);
        $coins = str_repeat("\x42", 64);
        $pair = ParagonIE_Sodium_Compat::crypto_kem_seed_keypair($seed);
        $this->assertSame(ParagonIE_Sodium_Compat::crypto_kem_xwing_seed_keypair($seed), $pair);
        $this->assertSame($pair, sodium_crypto_kem_seed_keypair($seed));
        $public = ParagonIE_Sodium_Compat::crypto_kem_publickey($pair);
        $secret = ParagonIE_Sodium_Compat::crypto_kem_secretkey($pair);
        $this->assertSame($pair, $secret . $public);
        $this->assertSame($public, sodium_crypto_kem_publickey($pair));
        $this->assertSame($secret, sodium_crypto_kem_secretkey($pair));
        $result = ParagonIE_Sodium_Compat::crypto_kem_enc_deterministic($public, $coins);
        $this->assertSame(ParagonIE_Sodium_Compat::crypto_kem_xwing_enc_deterministic($public, $coins), $result);
        $this->assertSame($result, sodium_crypto_kem_enc_deterministic($public, $coins));
        $this->assertSame($result[1], ParagonIE_Sodium_Compat::crypto_kem_dec($result[0], $secret));
        $this->assertSame($result[1], sodium_crypto_kem_dec($result[0], $secret));
        $pair = sodium_crypto_kem_keypair();
        $public = sodium_crypto_kem_publickey($pair);
        $secret = sodium_crypto_kem_secretkey($pair);
        $result = sodium_crypto_kem_enc($public);
        $this->assertSame($result[1], sodium_crypto_kem_dec($result[0], $secret));
        $result = ParagonIE_Sodium_Compat::crypto_kem_enc($public);
        $this->assertSame($result[1], ParagonIE_Sodium_Compat::crypto_kem_dec($result[0], $secret));
        $pair = ParagonIE_Sodium_Compat::crypto_kem_keypair();
        $this->assertSame(1248, strlen($pair));
    }

    public static function lowOrderPoints(): array
    {
        return [
            'zero' => [str_repeat("\0", 32)],
            'one' => ["\1" . str_repeat("\0", 31)]
        ];
    }

    /**
     * @dataProvider lowOrderPoints
     */
    #[DataProvider('lowOrderPoints')]
    public function testRejectsLowOrderPublicKey(string $point): void
    {
        $pair = ParagonIE_Sodium_Compat::crypto_kem_xwing_seed_keypair(str_repeat("\x23", 32));
        $public = ParagonIE_Sodium_Compat::crypto_kem_xwing_publickey($pair);
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::crypto_kem_xwing_enc_deterministic(
            substr($public, 0, 1184) . $point,
            str_repeat("\x42", 64)
        );
    }

    /**
     * @dataProvider lowOrderPoints
     * @throws SodiumException
     */
    #[DataProvider('lowOrderPoints')]
    public function testRejectsLowOrderCiphertext(string $point): void
    {
        $pair = ParagonIE_Sodium_Compat::crypto_kem_xwing_seed_keypair(str_repeat("\x23", 32));
        $public = ParagonIE_Sodium_Compat::crypto_kem_xwing_publickey($pair);
        $secret = ParagonIE_Sodium_Compat::crypto_kem_xwing_secretkey($pair);
        $result = ParagonIE_Sodium_Compat::crypto_kem_xwing_enc_deterministic($public, str_repeat("\x42", 64));
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::crypto_kem_xwing_dec(substr($result[0], 0, 1088) . $point, $secret);
    }

    /**
     * @before
     */
    #[Before]
    public function before(): void
    {
        $this->previousFallback = ParagonIE_Sodium_Compat::$disableFallbackForUnitTests;
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @after
     */
    #[After]
    public function after(): void
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = $this->previousFallback;
    }

    /**
     * @throws SodiumException
     */
    public function testRandomizedEncapsulationRoundTrip(): void
    {
        $keypair = ParagonIE_Sodium_Compat::crypto_kem_xwing_keypair();
        $this->assertSame(1248, strlen($keypair));
        $secret = ParagonIE_Sodium_Compat::crypto_kem_xwing_secretkey($keypair);
        $public = ParagonIE_Sodium_Compat::crypto_kem_xwing_publickey($keypair);
        $this->assertSame(32, strlen($secret));
        $this->assertSame(1216, strlen($public));
        $this->assertSame($secret . $public, $keypair);
        $result = ParagonIE_Sodium_Compat::crypto_kem_xwing_enc($public);
        $this->assertCount(2, $result);
        $this->assertSame(1120, strlen($result[0]));
        $this->assertSame(32, strlen($result[1]));
        $this->assertSame($result[1], ParagonIE_Sodium_Compat::crypto_kem_xwing_dec($result[0], $secret));
    }

    /**
     * @throws SodiumException
     */
    public function testCiphertextFaultProducesDifferentSharedSecret(): void
    {
        $keypair = ParagonIE_Sodium_Compat::crypto_kem_xwing_seed_keypair(str_repeat("\x23", 32));
        $secret = ParagonIE_Sodium_Compat::crypto_kem_xwing_secretkey($keypair);
        $public = ParagonIE_Sodium_Compat::crypto_kem_xwing_publickey($keypair);
        $result = ParagonIE_Sodium_Compat::crypto_kem_xwing_enc($public);
        $result[0][0] = $result[0][0] ^ "\x01";
        $rejected = ParagonIE_Sodium_Compat::crypto_kem_xwing_dec($result[0], $secret);
        $this->assertSame(32, strlen($rejected));
        $this->assertNotSame($result[1], $rejected);
    }

    /**
     * @throws SodiumException
     */
    public function testDecapsulationWithWrongKeyDoesNotRecoverSecret(): void
    {
        $pair = ParagonIE_Sodium_Compat::crypto_kem_xwing_keypair();
        $wrongPair = ParagonIE_Sodium_Compat::crypto_kem_xwing_keypair();
        $result = ParagonIE_Sodium_Compat::crypto_kem_xwing_enc(
            ParagonIE_Sodium_Compat::crypto_kem_xwing_publickey($pair)
        );
        $this->assertNotSame($result[1], ParagonIE_Sodium_Compat::crypto_kem_xwing_dec(
            $result[0],
            ParagonIE_Sodium_Compat::crypto_kem_xwing_secretkey($wrongPair)
        ));
    }

    public function testGlobalPolyfillRoundTrip(): void
    {
        $seed = str_repeat("\x35", 32);
        $this->assertSame(
            ParagonIE_Sodium_Compat::crypto_kem_xwing_seed_keypair($seed),
            sodium_crypto_kem_xwing_seed_keypair($seed)
        );
        $pair = sodium_crypto_kem_xwing_keypair();
        $public = sodium_crypto_kem_xwing_publickey($pair);
        $secret = sodium_crypto_kem_xwing_secretkey($pair);
        $this->assertSame($secret . $public, $pair);
        $result = sodium_crypto_kem_xwing_enc($public);
        $this->assertSame($result[1], sodium_crypto_kem_xwing_dec($result[0], $secret));
        $coins = str_repeat("\x42", 64);
        $this->assertSame(
            ParagonIE_Sodium_Compat::crypto_kem_xwing_enc_deterministic($public, $coins),
            sodium_crypto_kem_xwing_enc_deterministic($public, $coins)
        );
    }

    public static function malformedInputs(): array
    {
        return [
            'empty seed' => ['seed', 0], 'short seed' => ['seed', 32 - 1],
            'long seed' => ['seed', 32 + 1],
            'empty public key' => ['public', 0], 'short public key' => ['public', 1216 - 1],
            'long public key' => ['public', 1216 + 1],
            'empty secret key' => ['secret', 0], 'short secret key' => ['secret', 32 - 1],
            'long secret key' => ['secret', 32 + 1],
            'empty ciphertext' => ['ciphertext', 0], 'short ciphertext' => ['ciphertext', 1120 - 1],
            'long ciphertext' => ['ciphertext', 1120 + 1],
            'empty coins' => ['coins', 0], 'short coins' => ['coins', 64 - 1],
            'long coins' => ['coins', 64 + 1],
            'empty public extraction' => ['public extraction', 0],
            'short public extraction' => ['public extraction', 1248 - 1],
            'long public extraction' => ['public extraction', 1248 + 1],
            'empty secret extraction' => ['secret extraction', 0],
            'short secret extraction' => ['secret extraction', 1248 - 1],
            'long secret extraction' => ['secret extraction', 1248 + 1]
        ];
    }

    /**
     * @dataProvider malformedInputs
     * @throws SodiumException
     */
    #[DataProvider('malformedInputs')]
    public function testRejectsMalformedInputLengths(string $argument, int $length): void
    {
        // Keep other inputs valid so an unrelated validation cannot satisfy the assertion.
        $pair = ParagonIE_Sodium_Compat::crypto_kem_xwing_seed_keypair(str_repeat("\x23", 32));
        $public = ParagonIE_Sodium_Compat::crypto_kem_xwing_publickey($pair);
        $secret = ParagonIE_Sodium_Compat::crypto_kem_xwing_secretkey($pair);
        $ciphertext = $argument === 'secret' || $argument === 'ciphertext'
            ? ParagonIE_Sodium_Compat::crypto_kem_xwing_enc_deterministic($public, str_repeat("\x42", 64))[0]
            : '';
        $original = match ($argument) {
            'public' => $public,
            'secret' => $secret,
            'ciphertext' => $ciphertext,
            'public extraction', 'secret extraction' => $pair,
            default => ''
        };
        $value = str_pad(substr($original, 0, $length), $length, "\0");
        $this->expectException(SodiumException::class);
        switch ($argument) {
            case 'seed':
                ParagonIE_Sodium_Compat::crypto_kem_xwing_seed_keypair($value);
                break;
            case 'public':
                ParagonIE_Sodium_Compat::crypto_kem_xwing_enc($value);
                break;
            case 'secret':
                ParagonIE_Sodium_Compat::crypto_kem_xwing_dec($ciphertext, $value);
                break;
            case 'ciphertext':
                ParagonIE_Sodium_Compat::crypto_kem_xwing_dec($value, $secret);
                break;
            case 'coins':
                ParagonIE_Sodium_Compat::crypto_kem_xwing_enc_deterministic($public, $value);
                break;
            case 'public extraction':
                ParagonIE_Sodium_Compat::crypto_kem_xwing_publickey($value);
                break;
            case 'secret extraction':
                ParagonIE_Sodium_Compat::crypto_kem_xwing_secretkey($value);
                break;
        }
    }
}
