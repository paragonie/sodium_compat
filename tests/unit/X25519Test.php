<?php

/**
 * Class X25519Test
 */
class X25519Test extends PHPUnit_Framework_TestCase
{
    /**
     * @covers ParagonIE_Sodium_Core_X25519::crypto_scalarmult_curve25519_ref10_base()
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
