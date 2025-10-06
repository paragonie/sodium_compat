<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(ParagonIE_Sodium_Core_Poly1305::class)]
class CorePoly1305Test extends TestCase
{

    public function testInvalidKeyLengthAuth(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Key must be 32 bytes long.');
        ParagonIE_Sodium_Core_Poly1305::onetimeauth('message', random_bytes(31));
    }

    public function testInvalidKeyLengthVerify(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Key must be 32 bytes long.');
        ParagonIE_Sodium_Core_Poly1305::onetimeauth_verify(random_bytes(16), 'message', random_bytes(33));
    }
}
