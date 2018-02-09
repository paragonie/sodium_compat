<?php

class FileCompatTest extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        if (PHP_VERSION_ID < 70200) {
            $this->markTestSkipped('PHP < 7.2.0; skipping PHP 7.2 File compatibility test suite.');
        }
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * Ensure
     */
    public function testCompat()
    {
        $keypair = hex2bin(
            '5f2e1b83a832f890fc463fb3ff1cdf672e474eb07d26944d4c4bf5d385f49835' .
            '71932cdfd3990ec8026816f6a40198dbad5de646bc5f626df0e81810ada9db4b' .
            '71932cdfd3990ec8026816f6a40198dbad5de646bc5f626df0e81810ada9db4b'
        );
        $secret = sodium_crypto_sign_secretkey($keypair);
        $public = sodium_crypto_sign_publickey($keypair);

        $message = 'test';
        file_put_contents('test.txt', $message);
        $sigA = sodium_crypto_sign_detached($message, $secret);
        $sigB = ParagonIE_Sodium_File::sign('test.txt', $secret);

        $this->assertSame(
            bin2hex($sigA),
            bin2hex($sigB)
        );

        $this->assertTrue(ParagonIE_Sodium_File::verify($sigA, 'test.txt', $public));
        $this->assertTrue(sodium_crypto_sign_verify_detached($sigB, $message, $public));
    }
}
