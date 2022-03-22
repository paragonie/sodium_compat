<?php

class BoxSealTest extends PHPUnit_Framework_TestCase
{
    /**
     * @before
     */
    public function before()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    public function testSeal()
    {
        $keypair = ParagonIE_Sodium_Compat::crypto_box_keypair();
        $pk = ParagonIE_Sodium_Compat::crypto_box_publickey($keypair);

        $message = "This is a secret test message!\0\n";
        $sealed = ParagonIE_Sodium_Compat::crypto_box_seal($message, $pk);
        $opened = ParagonIE_Sodium_Compat::crypto_box_seal_open($sealed, $keypair);

        $this->assertSame($opened, $message);
    }
}
