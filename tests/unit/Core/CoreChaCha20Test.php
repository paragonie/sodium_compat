<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(ParagonIE_Sodium_Core_ChaCha20::class)]
class CoreChaCha20Test extends TestCase
{
    public function testRotate(): void
    {
        $this->assertSame(2, ParagonIE_Sodium_Core_ChaCha20::rotate(1, 1));
        $this->assertSame(4, ParagonIE_Sodium_Core_ChaCha20::rotate(1, 2));
        $this->assertSame(0x80000000, ParagonIE_Sodium_Core_ChaCha20::rotate(1, 31));
        $this->assertSame(1, ParagonIE_Sodium_Core_ChaCha20::rotate(1, 32));
    }

    /**
     * @throws Exception
     * @throws SodiumException
     */
    public function testStreamXorReversibility(): void
    {
        $key = random_bytes(32);
        $nonce = random_bytes(8);
        $message = 'the message';

        $encrypted = ParagonIE_Sodium_Core_ChaCha20::streamXorIc($message, $nonce, $key);
        $decrypted = ParagonIE_Sodium_Core_ChaCha20::streamXorIc($encrypted, $nonce, $key);

        $this->assertSame($message, $decrypted);
    }

    /**
     * @throws Exception
     * @throws SodiumException
     */
    public function testIetfStreamXorReversibility()
    {
        $key = random_bytes(32);
        $nonce = random_bytes(12);
        $message = 'the ietf message';

        $encrypted = ParagonIE_Sodium_Core_ChaCha20::ietfStreamXorIc($message, $nonce, $key);
        $decrypted = ParagonIE_Sodium_Core_ChaCha20::ietfStreamXorIc($encrypted, $nonce, $key);

        $this->assertSame($message, $decrypted);
    }

    /**
     * @see https://tools.ietf.org/html/rfc8439#section-2.4.2
     *
     * @throws Exception
     * @throws SodiumException
     */
    public function testRfc8439StreamVector(): void
    {
        $key = ParagonIE_Sodium_Core_Util::hex2bin('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
        $nonce = ParagonIE_Sodium_Core_Util::hex2bin('000000000000004a00000000'); // IETF nonce is 12 bytes
        $counter = ParagonIE_Sodium_Core_Util::store32_le(1);

        $ctx = new ParagonIE_Sodium_Core_ChaCha20_IetfCtx($key, $nonce, $counter);
        $plaintext = ParagonIE_Sodium_Core_Util::hex2bin(
            '4c616469657320616e642047656e746c656d656e206f662074686520636c6173'.
                '73206f66202739393a204966204920636f756c64206f6666657220796f75206f'.
                '6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73'.
                '637265656e20776f756c642062652069742e'
        );
        $stream = ParagonIE_Sodium_Core_ChaCha20::encryptBytes($ctx, $plaintext);
        
        $expected = 'e4e7f11091933c03c5d39b8b35583b48e64c3a2083b0ef5a28f5c3933f6a27e7' .
            'cb33e0e45b80a4303d8a2365e641b997d4155b389657094b223c880816e8853d';
        $expected = '6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b' .
            'f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf' .
            '500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6' .
            'b40b8eedf2785e42874d';

        $this->assertSame($expected, ParagonIE_Sodium_Core_Util::bin2hex($stream));
    }

    /**
     * @throws Exception
     * @throws SodiumException
     */
    public function testCounterOverflow(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Overflow');

        $key = str_repeat("\0", 32);
        $nonce = str_repeat("\0", 12);
        // Set counter to the value just before the overflow check triggers
        $counter = ParagonIE_Sodium_Core_Util::store32_le(0xf0000000 - 1);
        $ctx = new ParagonIE_Sodium_Core_ChaCha20_IetfCtx($key, $nonce, $counter);

        // Encrypting 64 bytes will succeed
        ParagonIE_Sodium_Core_ChaCha20::encryptBytes($ctx, str_repeat("\0", 64));
        // The next call will increment the counter and trigger the exception
        ParagonIE_Sodium_Core_ChaCha20::encryptBytes($ctx, str_repeat("\0", 64));
    }
}
