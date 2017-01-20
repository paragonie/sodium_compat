<?php

class Ed25519Test extends PHPUnit_Framework_TestCase
{
    public function testVectors()
    {
        $secretKey = ParagonIE_Sodium_Core_Util::hex2bin(
            'c4ffb94f252886b1378589af0d7d2004d9564b971ac73f09da827b80a5e39cd5' .
            'c50725d6a9b7df75a49f92accd3ab2cca4264a41d9c42cbd1e57eb2746e531d5'
        );
        $publicKey = ParagonIE_Sodium_Core_Ed25519::publickey_from_secretkey($secretKey);

        $this->assertSame(
            'c50725d6a9b7df75a49f92accd3ab2cca4264a41d9c42cbd1e57eb2746e531d5',
            bin2hex($publicKey)
        );

        $message = str_repeat("\x00", 128);
        $sig = ParagonIE_Sodium_Core_Ed25519::sign_detached($message, $secretKey);

        $this->assertSame(
            '8af8dee0f4e0396dac9f82078c6fff2587095fd2240543b6a723d603f47dfe72' .
            'cc7f315b0b666c5a68c736a0a0c3f0478fae1e73ae12ad6036ce0a9466f6b40e',
            bin2hex($sig),
            'Ed25519 signature'
        );

        $keypair = ParagonIE_Sodium_Core_Ed25519::keypair();
        $secretKey = ParagonIE_Sodium_Core_Ed25519::secretkey($keypair);
        $publicKey = ParagonIE_Sodium_Core_Ed25519::publickey($keypair);
        $sig = ParagonIE_Sodium_Core_Ed25519::sign_detached($message, $secretKey);

        $this->assertTrue(
            ParagonIE_Sodium_Core_Ed25519::verify_detached($sig, $message, $publicKey),
            'Ed25519 signature verification'
        );
    }
}
