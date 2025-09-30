<?php

use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class BoxSealTest extends TestCase
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
     */
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
