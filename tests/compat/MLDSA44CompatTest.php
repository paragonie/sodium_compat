<?php

use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class MLDSA44CompatTest extends TestCase
{
    private bool $previousFallback;

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

    public static function messages(): array
    {
        return [
            'empty' => [''],
            'binary' => ["\0binary\xffmessage"],
            'long' => [str_repeat('m', 1024)]
        ];
    }

    /**
     * @dataProvider messages
     * @throws SodiumException
     */
    #[DataProvider('messages')]
    public function testRandomizedSigningRoundTrip(string $message): void
    {
        $pair = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_keypair();
        $public = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_publickey($pair);
        $secret = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_secretkey($pair);
        $this->assertSame(3872, strlen($pair));
        $this->assertSame(1312, strlen($public));
        $this->assertSame(2560, strlen($secret));
        $this->assertSame($secret . $public, $pair);
        $signature = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_detached($message, $secret);
        $this->assertSame(2420, strlen($signature));
        $this->assertTrue(ParagonIE_Sodium_Compat::crypto_sign_mldsa44_verify_detached($signature, $message, $public));
    }

    public static function contexts(): array
    {
        return [
            'empty' => [''],
            'binary' => ["\0context\xff"],
            'maximum' => [str_repeat('c', 255)]
        ];
    }

    /**
     * @dataProvider contexts
     * @throws SodiumException
     */
    #[DataProvider('contexts')]
    public function testContextBinding(string $context): void
    {
        $pair = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_keypair();
        $public = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_publickey($pair);
        $secret = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_secretkey($pair);
        $signature = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_detached_ctx('message', $context, $secret);
        $this->assertTrue(
            ParagonIE_Sodium_Compat::crypto_sign_mldsa44_verify_detached_ctx($signature, 'message', $context, $public)
        );
        $changed = $context === '' ? 'different' : $context;
        $changed[0] = $changed[0] ^ "\x01";
        $this->assertFalse(
            ParagonIE_Sodium_Compat::crypto_sign_mldsa44_verify_detached_ctx($signature, 'message', $changed, $public)
        );
        if ($context === '') {
            $this->assertTrue(
                ParagonIE_Sodium_Compat::crypto_sign_mldsa44_verify_detached($signature, 'message', $public)
            );
        }
    }

    public static function signatureFaults(): array
    {
        return [
            'challenge' => ['signature', 0], 'response' => ['signature', 32],
            'hint padding or endpoint' => ['signature', 2419],
            'message' => ['message', 0], 'public key' => ['public', 0]
        ];
    }

    /**
     * @dataProvider signatureFaults
     * @throws SodiumException
     */
    #[DataProvider('signatureFaults')]
    public function testArtificialFaultsAreRejected(string $target, int $offset): void
    {
        $pair = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_seed_keypair(str_repeat('s', 32));
        $public = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_publickey($pair);
        $secret = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_secretkey($pair);
        $message = 'message';
        $signature = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_detached($message, $secret);
        if ($target === 'signature') {
            $signature[$offset] = $signature[$offset] ^ "\x01";
        } elseif ($target === 'message') {
            $message[$offset] = $message[$offset] ^ "\x01";
        } else {
            $public[$offset] = $public[$offset] ^ "\x01";
        }
        $this->assertFalse(ParagonIE_Sodium_Compat::crypto_sign_mldsa44_verify_detached($signature, $message, $public));
    }

    /**
     * @throws SodiumException
     */
    public function testWrongPublicKeyIsRejected(): void
    {
        $pair = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_keypair();
        $wrong = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_keypair();
        $signature = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_detached(
            'message',
            ParagonIE_Sodium_Compat::crypto_sign_mldsa44_secretkey($pair)
        );
        $this->assertFalse(ParagonIE_Sodium_Compat::crypto_sign_mldsa44_verify_detached(
            $signature,
            'message',
            ParagonIE_Sodium_Compat::crypto_sign_mldsa44_publickey($wrong)
        ));
    }

    public static function malformedInputs(): array
    {
        $cases = [];
        foreach (['seed' => 32, 'secret' => 2560, 'public' => 1312, 'signature' => 2420,
            'public extraction' => 3872, 'secret extraction' => 3872] as $argument => $size) {
            foreach ([0, $size - 1, $size + 1] as $length) {
                $cases[$argument . ' length=' . $length] = [$argument, $length];
            }
        }
        $cases['sign context over limit'] = ['sign context', 256];
        $cases['verify context over limit'] = ['verify context', 256];
        return $cases;
    }

    /**
     * @dataProvider malformedInputs
     * @throws SodiumException
     */
    #[DataProvider('malformedInputs')]
    public function testMalformedArgumentsThrow(string $argument, int $length): void
    {
        $pair = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_seed_keypair(str_repeat('s', 32));
        $public = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_publickey($pair);
        $secret = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_secretkey($pair);
        $signature = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_detached('message', $secret);
        $original = match ($argument) {
            'seed' => str_repeat('s', 32), 'secret' => $secret, 'public' => $public,
            'signature' => $signature, 'public extraction', 'secret extraction' => $pair,
            default => ''
        };
        $value = str_pad(substr($original, 0, $length), $length, "\0");
        $this->expectException(SodiumException::class);
        switch ($argument) {
            case 'seed':
                ParagonIE_Sodium_Compat::crypto_sign_mldsa44_seed_keypair($value);
                break;
            case 'secret':
                ParagonIE_Sodium_Compat::crypto_sign_mldsa44_detached('message', $value);
                break;
            case 'public':
                ParagonIE_Sodium_Compat::crypto_sign_mldsa44_verify_detached($signature, 'message', $value);
                break;
            case 'signature':
                ParagonIE_Sodium_Compat::crypto_sign_mldsa44_verify_detached($value, 'message', $public);
                break;
            case 'sign context':
                ParagonIE_Sodium_Compat::crypto_sign_mldsa44_detached_ctx('message', $value, $secret);
                break;
            case 'verify context':
                ParagonIE_Sodium_Compat::crypto_sign_mldsa44_verify_detached_ctx(
                    $signature,
                    'message',
                    $value,
                    $public
                );
                break;
            case 'public extraction':
                ParagonIE_Sodium_Compat::crypto_sign_mldsa44_publickey($value);
                break;
            case 'secret extraction':
                ParagonIE_Sodium_Compat::crypto_sign_mldsa44_secretkey($value);
                break;
        }
    }

    public static function invalidSecretCoefficients(): array
    {
        return [
            's1 first' => [128],
            's1 last' => [511],
            's2 first' => [512],
            's2 last' => [895]
        ];
    }

    /**
     * @dataProvider invalidSecretCoefficients
     * @throws SodiumException
     */
    #[DataProvider('invalidSecretCoefficients')]
    public function testRejectsInvalidEtaCoefficients(int $offset): void
    {
        $pair = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_seed_keypair(str_repeat('s', 32));
        $secret = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_secretkey($pair);
        $secret[$offset] = "\xff";
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::crypto_sign_mldsa44_detached('message', $secret);
    }

    public function testGlobalPolyfillWithAndWithoutContext(): void
    {
        $seed = str_repeat('s', 32);
        $this->assertSame(
            ParagonIE_Sodium_Compat::crypto_sign_mldsa44_seed_keypair($seed),
            sodium_crypto_sign_mldsa44_seed_keypair($seed)
        );
        $pair = sodium_crypto_sign_mldsa44_keypair();
        $secret = sodium_crypto_sign_mldsa44_secretkey($pair);
        $public = sodium_crypto_sign_mldsa44_publickey($pair);
        $this->assertSame($secret . $public, $pair);
        $signature = sodium_crypto_sign_mldsa44_detached('message', $secret);
        $this->assertTrue(sodium_crypto_sign_mldsa44_verify_detached($signature, 'message', $public));
        $signature = sodium_crypto_sign_mldsa44_detached_ctx('message', 'context', $secret);
        $this->assertTrue(sodium_crypto_sign_mldsa44_verify_detached_ctx($signature, 'message', 'context', $public));
        $this->assertFalse(sodium_crypto_sign_mldsa44_verify_detached_ctx($signature, 'message', 'wrong', $public));
    }
}
