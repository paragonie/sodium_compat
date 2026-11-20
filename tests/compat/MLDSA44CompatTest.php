<?php

/**
 * @covers ParagonIE_Sodium_Compat
 */
class MLDSA44CompatTest extends PHPUnit_Framework_TestCase
{
    /**
     * @var bool $previousFallback
     */
    private $previousFallback;

    /**
     * @before
     */
    public function before()
    {
        $this->previousFallback = ParagonIE_Sodium_Compat::$disableFallbackForUnitTests;
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @after
     */
    public function after()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = $this->previousFallback;
    }

    public static function messages()
    {
        return array(
            'empty' => array(''),
            'binary' => array("\0binary\xffmessage"),
            'long' => array(str_repeat('m', 1024))
        );
    }

    /**
     * @dataProvider messages
     * @throws SodiumException
     */
    public function testRandomizedSigningRoundTrip($message)
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

    public static function contexts()
    {
        return array(
            'empty' => array(''),
            'binary' => array("\0context\xff"),
            'maximum' => array(str_repeat('c', 255))
        );
    }

    /**
     * @dataProvider contexts
     * @throws SodiumException
     */
    public function testContextBinding($context)
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

    public static function signatureFaults()
    {
        return array(
            'challenge' => array('signature', 0), 'response' => array('signature', 32),
            'hint padding or endpoint' => array('signature', 2419),
            'message' => array('message', 0), 'public key' => array('public', 0)
        );
    }

    /**
     * @dataProvider signatureFaults
     * @throws SodiumException
     */
    public function testArtificialFaultsAreRejected($target, $offset)
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
    public function testWrongPublicKeyIsRejected()
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

    public static function malformedInputs()
    {
        $cases = array();
        foreach (array('seed' => 32, 'secret' => 2560, 'public' => 1312, 'signature' => 2420,
            'public extraction' => 3872, 'secret extraction' => 3872) as $argument => $size) {
            foreach (array(0, $size - 1, $size + 1) as $length) {
                $cases[$argument . ' length=' . $length] = array($argument, $length);
            }
        }
        $cases['sign context over limit'] = array('sign context', 256);
        $cases['verify context over limit'] = array('verify context', 256);
        return $cases;
    }

    /**
     * @dataProvider malformedInputs
     * @throws SodiumException
     */
    public function testMalformedArgumentsThrow($argument, $length)
    {
        $pair = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_seed_keypair(str_repeat('s', 32));
        $public = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_publickey($pair);
        $secret = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_secretkey($pair);
        $signature = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_detached('message', $secret);
        $original = '';
        switch ($argument) {
            case 'seed':
                $original = str_repeat('s', 32);
                break;
            case 'secret':
                $original = $secret;
                break;
            case 'public':
                $original = $public;
                break;
            case 'signature':
                $original = $signature;
                break;
            case 'public extraction':
            case 'secret extraction':
                $original = $pair;
                break;
        }
        $value = str_pad(substr($original, 0, $length), $length, "\0");
        if (method_exists($this, 'expectException')) {
            $this->expectException('SodiumException');
        } else {
            $this->setExpectedException('SodiumException');
        }
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

    public static function invalidSecretCoefficients()
    {
        return array(
            's1 first' => array(128),
            's1 last' => array(511),
            's2 first' => array(512),
            's2 last' => array(895)
        );
    }

    /**
     * @dataProvider invalidSecretCoefficients
     * @throws SodiumException
     */
    public function testRejectsInvalidEtaCoefficients($offset)
    {
        $pair = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_seed_keypair(str_repeat('s', 32));
        $secret = ParagonIE_Sodium_Compat::crypto_sign_mldsa44_secretkey($pair);
        $secret[$offset] = "\xff";
        if (method_exists($this, 'expectException')) {
            $this->expectException('SodiumException');
        } else {
            $this->setExpectedException('SodiumException');
        }
        ParagonIE_Sodium_Compat::crypto_sign_mldsa44_detached('message', $secret);
    }

    /**
     * @throws SodiumException
     */
    public function testGlobalPolyfillWithAndWithoutContext()
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
