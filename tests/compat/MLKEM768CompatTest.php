<?php

/**
 * @covers ParagonIE_Sodium_Compat
 */
class MLKEM768CompatTest extends PHPUnit_Framework_TestCase
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

    /**
     * @throws SodiumException
     */
    public function testRandomizedEncapsulationRoundTrip()
    {
        $keypair = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_keypair();
        $this->assertSame(3584, strlen($keypair));
        $secret = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_secretkey($keypair);
        $public = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_publickey($keypair);
        $this->assertSame(2400, strlen($secret));
        $this->assertSame(1184, strlen($public));
        $this->assertSame($secret . $public, $keypair);
        $result = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_enc($public);
        $this->assertCount(2, $result);
        $this->assertSame(1088, strlen($result[0]));
        $this->assertSame(32, strlen($result[1]));
        $this->assertSame($result[1], ParagonIE_Sodium_Compat::crypto_kem_mlkem768_dec($result[0], $secret));
    }

    /**
     * @throws SodiumException
     */
    public function testCiphertextFaultProducesDifferentSharedSecret()
    {
        $keypair = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_seed_keypair(str_repeat("\x23", 64));
        $secret = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_secretkey($keypair);
        $public = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_publickey($keypair);
        $result = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_enc($public);
        $result[0][0] = $result[0][0] ^ "\x01";
        $rejected = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_dec($result[0], $secret);
        $this->assertSame(32, strlen($rejected));
        $this->assertNotSame($result[1], $rejected);
    }

    /**
     * @throws SodiumException
     */
    public function testDecapsulationWithWrongKeyDoesNotRecoverSecret()
    {
        $pair = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_keypair();
        $wrongPair = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_keypair();
        $result = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_enc(
            ParagonIE_Sodium_Compat::crypto_kem_mlkem768_publickey($pair)
        );
        $this->assertNotSame($result[1], ParagonIE_Sodium_Compat::crypto_kem_mlkem768_dec(
            $result[0],
            ParagonIE_Sodium_Compat::crypto_kem_mlkem768_secretkey($wrongPair)
        ));
    }

    /**
     * @throws SodiumException
     */
    public function testGlobalPolyfillRoundTrip()
    {
        $seed = str_repeat("\x35", 64);
        $this->assertSame(
            ParagonIE_Sodium_Compat::crypto_kem_mlkem768_seed_keypair($seed),
            sodium_crypto_kem_mlkem768_seed_keypair($seed)
        );
        $pair = sodium_crypto_kem_mlkem768_keypair();
        $public = sodium_crypto_kem_mlkem768_publickey($pair);
        $secret = sodium_crypto_kem_mlkem768_secretkey($pair);
        $this->assertSame($secret . $public, $pair);
        $result = sodium_crypto_kem_mlkem768_enc($public);
        $this->assertSame($result[1], sodium_crypto_kem_mlkem768_dec($result[0], $secret));
        $coins = str_repeat("\x42", 32);
        $this->assertSame(
            ParagonIE_Sodium_Compat::crypto_kem_mlkem768_enc_deterministic($public, $coins),
            sodium_crypto_kem_mlkem768_enc_deterministic($public, $coins)
        );
    }

    public static function malformedInputs()
    {
        return array(
            'empty seed' => array('seed', 0), 'short seed' => array('seed', 64 - 1),
            'long seed' => array('seed', 64 + 1),
            'empty public key' => array('public', 0), 'short public key' => array('public', 1184 - 1),
            'long public key' => array('public', 1184 + 1),
            'empty secret key' => array('secret', 0), 'short secret key' => array('secret', 2400 - 1),
            'long secret key' => array('secret', 2400 + 1),
            'empty ciphertext' => array('ciphertext', 0), 'short ciphertext' => array('ciphertext', 1088 - 1),
            'long ciphertext' => array('ciphertext', 1088 + 1),
            'empty coins' => array('coins', 0), 'short coins' => array('coins', 32 - 1),
            'long coins' => array('coins', 32 + 1),
            'empty public extraction' => array('public extraction', 0),
            'short public extraction' => array('public extraction', 3584 - 1),
            'long public extraction' => array('public extraction', 3584 + 1),
            'empty secret extraction' => array('secret extraction', 0),
            'short secret extraction' => array('secret extraction', 3584 - 1),
            'long secret extraction' => array('secret extraction', 3584 + 1)
        );
    }

    /**
     * @dataProvider malformedInputs
     * @throws SodiumException
     */
    public function testRejectsMalformedInputLengths($argument, $length)
    {
        // Keep other inputs valid so an unrelated validation cannot satisfy the assertion.
        $pair = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_seed_keypair(str_repeat("\x23", 64));
        $public = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_publickey($pair);
        $secret = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_secretkey($pair);
        $ciphertext = '';
        if ($argument === 'secret' || $argument === 'ciphertext') {
            $encapsulation = ParagonIE_Sodium_Compat::crypto_kem_mlkem768_enc_deterministic($public, str_repeat("\x42", 32));
            $ciphertext = $encapsulation[0];
        }
        $original = '';
        switch ($argument) {
            case 'public':
                $original = $public;
                break;
            case 'secret':
                $original = $secret;
                break;
            case 'ciphertext':
                $original = $ciphertext;
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
                ParagonIE_Sodium_Compat::crypto_kem_mlkem768_seed_keypair($value);
                break;
            case 'public':
                ParagonIE_Sodium_Compat::crypto_kem_mlkem768_enc($value);
                break;
            case 'secret':
                ParagonIE_Sodium_Compat::crypto_kem_mlkem768_dec($ciphertext, $value);
                break;
            case 'ciphertext':
                ParagonIE_Sodium_Compat::crypto_kem_mlkem768_dec($value, $secret);
                break;
            case 'coins':
                ParagonIE_Sodium_Compat::crypto_kem_mlkem768_enc_deterministic($public, $value);
                break;
            case 'public extraction':
                ParagonIE_Sodium_Compat::crypto_kem_mlkem768_publickey($value);
                break;
            case 'secret extraction':
                ParagonIE_Sodium_Compat::crypto_kem_mlkem768_secretkey($value);
                break;
        }
    }
}
