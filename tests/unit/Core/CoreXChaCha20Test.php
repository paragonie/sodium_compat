<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(ParagonIE_Sodium_Core_XChaCha20::class)]
class CoreXChaCha20Test extends TestCase
{
    /**
     * @throws Exception
     * @throws SodiumException
     */
    public function testStreamXorReversibility(): void
    {
        $key = random_bytes(32);
        $nonce = random_bytes(24);
        $message = 'the xchacha20 message';

        $encrypted = ParagonIE_Sodium_Core_XChaCha20::streamXorIc($message, $nonce, $key);
        $decrypted = ParagonIE_Sodium_Core_XChaCha20::streamXorIc($encrypted, $nonce, $key);

        $this->assertSame($message, $decrypted);
    }

    /**
     * @return void
     * @throws SodiumException
     */
    public function testIetfStreamXorReversibility(): void
    {
        $key = random_bytes(32);
        $nonce = random_bytes(24);
        $message = 'the ietf xchacha20 message';

        $encrypted = ParagonIE_Sodium_Core_XChaCha20::ietfStreamXorIc($message, $nonce, $key);
        $decrypted = ParagonIE_Sodium_Core_XChaCha20::ietfStreamXorIc($encrypted, $nonce, $key);

        $this->assertSame($message, $decrypted);
    }

    /**
     * @see https://tools.ietf.org/html/draft-arciszewski-xchacha-03#section-2.2.3
     */
    public function testIetfDraftVector()
    {
        $key = ParagonIE_Sodium_Core_Util::hex2bin(
            '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
        );
        $nonce = ParagonIE_Sodium_Core_Util::hex2bin(
            '404142434445464748494a4b4c4d4e4f5051525354555658'
        );
        $plaintext = ParagonIE_Sodium_Core_Util::hex2bin(
            '5468652064686f6c65202870726f6e6f756e6365642022646f6c652229206973' .
            '20616c736f206b6e6f776e2061732074686520417369617469632077696c6420' .
            '646f672c2072656420646f672c20616e642077686973746c696e6720646f672e' .
            '2049742069732061626f7574207468652073697a65206f662061204765726d61' .
            '6e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061' .
            '206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c' .
            '757369766520616e6420736b696c6c6564206a756d70657220697320636c6173' .
            '736966696564207769746820776f6c7665732c20636f796f7465732c206a6163' .
            '6b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d6963' .
            '2066616d696c792043616e696461652e'
        );
        $expectedCiphertext = '7d0a2e6b7f7c65a236542630294e063b7ab9b555a5d5149aa21e4ae1e4fbce87' .
            'ecc8e08a8b5e350abe622b2ffa617b202cfad72032a3037e76ffdcdc4376ee05' .
            '3a190d7e46ca1de04144850381b9cb29f051915386b8a710b8ac4d027b8b050f' .
            '7cba5854e028d564e453b8a968824173fc16488b8970cac828f11ae53cabd201' .
            '12f87107df24ee6183d2274fe4c8b1485534ef2c5fbc1ec24bfc3663efaa08bc' .
            '047d29d25043532db8391a8a3d776bf4372a6955827ccb0cdd4af403a7ce4c63' .
            'd595c75a43e045f0cce1f29c8b93bd65afc5974922f214a40b7c402cdb91ae73' .
            'c0b63615cdad0480680f16515a7ace9d39236464328a37743ffc28f4ddb324f4' .
            'd0f5bbdc270c65b1749a6efff1fbaa09536175ccd29fb9e6057b307320d31683' .
            '8a9c71f70b5b5907a66f7ea49aadc409';

        // The draft specifies a block counter of 1. This is a 4-byte little-endian value for IETF.
        $ic = "\x01\x00\x00\x00";
        $encrypted = ParagonIE_Sodium_Core_XChaCha20::ietfStreamXorIc($plaintext, $nonce, $key, $ic);
        $this->assertSame(
            $expectedCiphertext,
            ParagonIE_Sodium_Core_Util::bin2hex($encrypted)
        );
    }

    public function testInvalidNonceLength(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Nonce must be 24 bytes long');

        ParagonIE_Sodium_Core_XChaCha20::stream(10, random_bytes(23), random_bytes(32));
    }

    public function testInvalidNonceLengthIetf(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Nonce must be 24 bytes long');

        ParagonIE_Sodium_Core_XChaCha20::ietfStream(10, random_bytes(25), random_bytes(32));
    }
}
