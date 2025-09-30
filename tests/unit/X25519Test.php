<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\CoversClass;

/**
 * Class X25519Test
 */
#[CoversClass(ParagonIE_Sodium_Core_X25519::class)]
class X25519Test extends TestCase
{
    /**
     * @before
     */
    #[Before]
    public function before(): void
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @throws SodiumException
     * @throws TypeError
     */
    public function testScalarmultBase(): void
    {
        $alice_secret = ParagonIE_Sodium_Core_Util::hex2bin('69f208412d8dd5db9d0c6d18512e86f0ec75665ab841372d57b042b27ef89d8c');
        $alice_public = ParagonIE_Sodium_Core_Util::hex2bin('ac3a70ba35df3c3fae427a7c72021d68f2c1e044040b75f17313c0c8b5d4241d');

        $this->assertSame(
            bin2hex($alice_public),
            bin2hex(ParagonIE_Sodium_Crypto::scalarmult_base($alice_secret))
        );
    }

    /**
     * @throws SodiumException
     * @throws TypeError
     */
    public function testRef10(): void
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

    /**
     * @throws SodiumException
     * @throws TypeError
     */
    public function testScalarmultZeroForLegacyPhpUnit(): void
    {
        $this->expectException(SodiumException::class);
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

    /**
     * @throws SodiumException
     * @throws TypeError
     */
    public function testScalarmultZero(): void
    {
        $this->expectException(SodiumException::class);
        $aliceSk = ParagonIE_Sodium_Core_Util::hex2bin(
            'b75b0a8b25c58aaef1d14fc9ce2bbaeac607407d1ade104aeaa196f8ac13b93f'
        );
        $bobPk = ParagonIE_Sodium_Core_Util::hex2bin(
            str_repeat('0', 64)
        );

        $this->expectException('SodiumException');

        $this->assertNotSame(
            $bobPk,
            ParagonIE_Sodium_Core_Util::bin2hex(
                ParagonIE_Sodium_Compat::crypto_scalarmult($aliceSk, $bobPk)
            ),
            'test'
        );
    }
}
