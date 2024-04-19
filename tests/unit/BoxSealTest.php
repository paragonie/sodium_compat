<?php
use PHPUnit\Framework\TestCase;

class BoxSealTest extends TestCase
{
    /**
     * @before
     */
    public function before(): void
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    public function testSeal(): void
    {
        $keypair = ParagonIE_Sodium_Compat::crypto_box_keypair();
        $pk = ParagonIE_Sodium_Compat::crypto_box_publickey($keypair);

        $message = "This is a secret test message!\0\n";
        $sealed = ParagonIE_Sodium_Compat::crypto_box_seal($message, $pk);
        $opened = ParagonIE_Sodium_Compat::crypto_box_seal_open($sealed, $keypair);

        $this->assertSame($opened, $message);
    }
}
