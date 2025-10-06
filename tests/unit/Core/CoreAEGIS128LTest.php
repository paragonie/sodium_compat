<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(ParagonIE_Sodium_Core_AEGIS128L::class)]
class CoreAEGIS128LTest extends TestCase
{
    public function testEncryptDecrypt()
    {
        $key = random_bytes(16);
        $nonce = random_bytes(16);
        $ad = random_bytes(32);
        $message = 'Squeamish Ossifrage';

        list($ct, $tag) = ParagonIE_Sodium_Core_AEGIS128L::encrypt($message, $ad, $key, $nonce);
        $decrypted = ParagonIE_Sodium_Core_AEGIS128L::decrypt($ct, $tag, $ad, $key, $nonce);
        $this->assertSame($message, $decrypted);
    }

    public function testDecryptFail()
    {
        $key = random_bytes(16);
        $nonce = random_bytes(16);
        $ad = random_bytes(32);
        $message = 'Squeamish Ossifrage';

        list($ct, $tag) = ParagonIE_Sodium_Core_AEGIS128L::encrypt($message, $ad, $key, $nonce);

        // Wrong Key
        try {
            ParagonIE_Sodium_Core_AEGIS128L::decrypt($ct, $tag, $ad, random_bytes(16), $nonce);
            $this->fail('Should have thrown an exception');
        } catch (SodiumException $ex) {
            $this->assertSame('verification failed', $ex->getMessage());
        }

        // Wrong Nonce
        try {
            ParagonIE_Sodium_Core_AEGIS128L::decrypt($ct, $tag, $ad, $key, random_bytes(16));
            $this->fail('Should have thrown an exception');
        } catch (SodiumException $ex) {
            $this->assertSame('verification failed', $ex->getMessage());
        }

        // Wrong AD
        try {
            ParagonIE_Sodium_Core_AEGIS128L::decrypt($ct, $tag, random_bytes(32), $key, $nonce);
            $this->fail('Should have thrown an exception');
        } catch (SodiumException $ex) {
            $this->assertSame('verification failed', $ex->getMessage());
        }

        // Wrong Tag
        try {
            ParagonIE_Sodium_Core_AEGIS128L::decrypt($ct, random_bytes(32), $ad, $key, $nonce);
            $this->fail('Should have thrown an exception');
        } catch (SodiumException $ex) {
            $this->assertSame('verification failed', $ex->getMessage());
        }
    }
}
