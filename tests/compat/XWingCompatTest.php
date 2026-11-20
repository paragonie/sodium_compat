<?php

/**
 * @covers ParagonIE_Sodium_Compat
 */
class XWingCompatTest extends PHPUnit_Framework_TestCase
{
    private $previousFallback;

    /**
     * @throws SodiumException
     */
    public function testGenericKEMAliasesUseXWing()
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

    public static function lowOrderPoints()
    {
        return array(
            'zero' => array(str_repeat("\0", 32)),
            'one' => array("\1" . str_repeat("\0", 31))
        );
    }

    /**
     * @dataProvider lowOrderPoints
     */
    public function testRejectsLowOrderPublicKey($point)
    {
        $pair = ParagonIE_Sodium_Compat::crypto_kem_xwing_seed_keypair(str_repeat("\x23", 32));
        $public = ParagonIE_Sodium_Compat::crypto_kem_xwing_publickey($pair);
        if (method_exists($this, 'expectException')) {
            $this->expectException('SodiumException');
        } else {
            $this->setExpectedException('SodiumException');
        }
        ParagonIE_Sodium_Compat::crypto_kem_xwing_enc_deterministic(
            substr($public, 0, 1184) . $point,
            str_repeat("\x42", 64)
        );
    }

    /**
     * @dataProvider lowOrderPoints
     * @throws SodiumException
     */
    public function testRejectsLowOrderCiphertext($point)
    {
        $pair = ParagonIE_Sodium_Compat::crypto_kem_xwing_seed_keypair(str_repeat("\x23", 32));
        $public = ParagonIE_Sodium_Compat::crypto_kem_xwing_publickey($pair);
        $secret = ParagonIE_Sodium_Compat::crypto_kem_xwing_secretkey($pair);
        $result = ParagonIE_Sodium_Compat::crypto_kem_xwing_enc_deterministic($public, str_repeat("\x42", 64));
        if (method_exists($this, 'expectException')) {
            $this->expectException('SodiumException');
        } else {
            $this->setExpectedException('SodiumException');
        }
        ParagonIE_Sodium_Compat::crypto_kem_xwing_dec(substr($result[0], 0, 1088) . $point, $secret);
    }

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
    public function testCiphertextFaultProducesDifferentSharedSecret()
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
    public function testDecapsulationWithWrongKeyDoesNotRecoverSecret()
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

    public function testGlobalPolyfillRoundTrip()
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

    public static function malformedInputs()
    {
        return array(
            'empty seed' => array('seed', 0), 'short seed' => array('seed', 32 - 1),
            'long seed' => array('seed', 32 + 1),
            'empty public key' => array('public', 0), 'short public key' => array('public', 1216 - 1),
            'long public key' => array('public', 1216 + 1),
            'empty secret key' => array('secret', 0), 'short secret key' => array('secret', 32 - 1),
            'long secret key' => array('secret', 32 + 1),
            'empty ciphertext' => array('ciphertext', 0), 'short ciphertext' => array('ciphertext', 1120 - 1),
            'long ciphertext' => array('ciphertext', 1120 + 1),
            'empty coins' => array('coins', 0), 'short coins' => array('coins', 64 - 1),
            'long coins' => array('coins', 64 + 1),
            'empty public extraction' => array('public extraction', 0),
            'short public extraction' => array('public extraction', 1248 - 1),
            'long public extraction' => array('public extraction', 1248 + 1),
            'empty secret extraction' => array('secret extraction', 0),
            'short secret extraction' => array('secret extraction', 1248 - 1),
            'long secret extraction' => array('secret extraction', 1248 + 1)
        );
    }

    /**
     * @dataProvider malformedInputs
     * @throws SodiumException
     */
    public function testRejectsMalformedInputLengths($argument, $length)
    {
        // Keep other inputs valid so an unrelated validation cannot satisfy the assertion.
        $pair = ParagonIE_Sodium_Compat::crypto_kem_xwing_seed_keypair(str_repeat("\x23", 32));
        $public = ParagonIE_Sodium_Compat::crypto_kem_xwing_publickey($pair);
        $secret = ParagonIE_Sodium_Compat::crypto_kem_xwing_secretkey($pair);
        $ciphertext = '';
        if ($argument === 'secret' || $argument === 'ciphertext') {
            $encapsulation = ParagonIE_Sodium_Compat::crypto_kem_xwing_enc_deterministic($public, str_repeat("\x42", 64));
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
