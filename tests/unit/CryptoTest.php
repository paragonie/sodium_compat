<?php

class CryptoTest extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    public function testScalarmultBase()
    {
        $alice_secret = hex2bin('69f208412d8dd5db9d0c6d18512e86f0ec75665ab841372d57b042b27ef89d8c');
        $alice_public = hex2bin('ac3a70ba35df3c3fae427a7c72021d68f2c1e044040b75f17313c0c8b5d4241d');

        $this->assertSame(
            bin2hex($alice_public),
            bin2hex(ParagonIE_Sodium_Crypto::scalarmult_base($alice_secret))
        );
    }

    public function testScalarmult()
    {
        $alice_secret = hex2bin('69f208412d8dd5db9d0c6d18512e86f0ec75665ab841372d57b042b27ef89d8c');
        $alice_public = hex2bin('ac3a70ba35df3c3fae427a7c72021d68f2c1e044040b75f17313c0c8b5d4241d');
        $bob_secret = hex2bin('b581fb5ae182a16f603f39270d4e3b95bc008310b727a11dd4e784a0044d461b');
        $bob_public = hex2bin('e8980c86e032f1eb2975052e8d65bddd15c3b59641174ec9678a53789d92c754');

        $this->assertSame(
            bin2hex(ParagonIE_Sodium_Crypto::scalarmult($alice_secret, $bob_public)),
            bin2hex(ParagonIE_Sodium_Crypto::scalarmult($bob_secret, $alice_public))
        );
    }

    public function testSignDetached()
    {
        $secret = hex2bin(
            'fcdf31aae72e280cc760186d83e41be216fe1f2c7407dd393ad3a45a2fa501a4' .
            'ee00f800ae9e986b994ec0af67fe6b017eb78704e81639eee7efa3d3a831d1bc'
        );
        $message = 'Test message';
        $this->assertSame(
            '5e413e791d9bcdbaa1cfd4f83b01c73926f436a467cfc2634fc90651fb0465bfea76083b4ff247f925df96e89da3d9edc11029adf1601cd0f97d1b2c4b02e905',
            bin2hex(ParagonIE_Sodium_Crypto::sign_detached($message, $secret)),
            'Generated different signatures'
        );

        $message = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.';
        $this->assertSame(
            '36a6d2748f6ab8f76c122a562d55343cb7c6f15c8a45bd55bd8b9e9fadd2363f370cb78fba42c550d487b9bd7413312b6490c8b3ee2cea638997172a9c8c250f',
            bin2hex(ParagonIE_Sodium_Crypto::sign_detached($message, $secret)),
            'Generated different signatures'
        );
    }

    public function testVerifyDetached()
    {
        $public = hex2bin('ee00f800ae9e986b994ec0af67fe6b017eb78704e81639eee7efa3d3a831d1bc');

        $message = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.';
        $sig = hex2bin(
            '36a6d2748f6ab8f76c122a562d55343cb7c6f15c8a45bd55bd8b9e9fadd2363f' .
            '370cb78fba42c550d487b9bd7413312b6490c8b3ee2cea638997172a9c8c250f'
        );
        $this->assertTrue(
            ParagonIE_Sodium_Crypto::sign_verify_detached($sig, $message, $public),
            'Invalid signature verification checking'
        );
    }
}
