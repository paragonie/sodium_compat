<?php

/**
 * Class X25519Test
 */
class X25519Test extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @covers ParagonIE_Sodium_Crypto::scalarmult_base()
     * @throws SodiumException
     * @throws TypeError
     */
    public function testScalarmultBase()
    {
        $alice_secret = ParagonIE_Sodium_Core_Util::hex2bin('69f208412d8dd5db9d0c6d18512e86f0ec75665ab841372d57b042b27ef89d8c');
        $alice_public = ParagonIE_Sodium_Core_Util::hex2bin('ac3a70ba35df3c3fae427a7c72021d68f2c1e044040b75f17313c0c8b5d4241d');

        if (PHP_INT_SIZE === 4) {
            $this->assertSame(
                bin2hex($alice_public),
                bin2hex(ParagonIE_Sodium_Crypto32::scalarmult_base($alice_secret))
            );
        } else {
            $this->assertSame(
                bin2hex($alice_public),
                bin2hex(ParagonIE_Sodium_Crypto::scalarmult_base($alice_secret))
            );
        }
    }

    /**
     * @covers ParagonIE_Sodium_Core_X25519::crypto_scalarmult_curve25519_ref10_base()
     * @throws SodiumException
     * @throws TypeError
     */
    public function testRef10()
    {
        $staticSk = ParagonIE_Sodium_Core_Util::hex2bin(
            'b75b0a8b25c58aaef1d14fc9ce2bbaeac607407d1ade104aeaa196f8ac13b93f'
        );
        $staticPk = ParagonIE_Sodium_Core_Util::hex2bin(
            '9b29186b7afb95caf85ceabc9687fd1a5d82290170075b519d6a449c751bb337'
        );

        $secretKey = random_bytes(32);

        if (PHP_INT_SIZE === 4) {
            $publicKey = ParagonIE_Sodium_Core32_X25519::crypto_scalarmult_curve25519_ref10_base($secretKey);
            $this->assertSame(
                ParagonIE_Sodium_Core32_Util::bin2hex(
                    ParagonIE_Sodium_Core32_X25519::crypto_scalarmult_curve25519_ref10($staticSk, $publicKey)
                ),
                ParagonIE_Sodium_Core32_Util::bin2hex(
                    ParagonIE_Sodium_Core32_X25519::crypto_scalarmult_curve25519_ref10($secretKey, $staticPk)
                ),
                'Elliptic Curve Diffie-Hellman over Curve25519 is failing'
            );
        } else {
            $publicKey = ParagonIE_Sodium_Core_X25519::crypto_scalarmult_curve25519_ref10_base($secretKey);
            $this->assertSame(
                ParagonIE_Sodium_Core_Util::bin2hex(
                    ParagonIE_Sodium_Core_X25519::crypto_scalarmult_curve25519_ref10($staticSk, $publicKey)
                ),
                ParagonIE_Sodium_Core_Util::bin2hex(
                    ParagonIE_Sodium_Core_X25519::crypto_scalarmult_curve25519_ref10($secretKey, $staticPk)
                ),
                'Elliptic Curve Diffie-Hellman over Curve25519 is failing'
            );
        }
    }

    /**
     * @expectedException SodiumException
     * @throws SodiumException
     * @throws TypeError
     */
    public function testScalarmultZero()
    {
        $aliceSk = ParagonIE_Sodium_Core_Util::hex2bin(
            'b75b0a8b25c58aaef1d14fc9ce2bbaeac607407d1ade104aeaa196f8ac13b93f'
        );
        $bobPk = ParagonIE_Sodium_Core_Util::hex2bin(
            str_repeat('0', 64)
        );
        $this->assertNotSame(
            $bobPk,
            ParagonIE_Sodium_Core_Util::bin2hex(
                ParagonIE_Sodium_Compat::crypto_scalarmult($aliceSk, $bobPk)
            ),
            'test'
        );
    }
}
