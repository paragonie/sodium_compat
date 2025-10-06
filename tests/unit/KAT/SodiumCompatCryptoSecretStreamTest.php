<?php

use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class SodiumCompatCryptoSecretStreamTest extends KnownAnswerTestCase
{
    public function testCryptoSecretStream(): void
    {
        // 1. Key Generation
        $key = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_keygen();
        $this->assertSame(32, strlen($key));

        // 2. Initialization
        list($push_state, $header) = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_init_push($key);
        $pull_state = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_init_pull($header, $key);

        // 3. First message
        $message1 = 'This is the first message.';
        $tag1 = ParagonIE_Sodium_Compat::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH;
        $encrypted1 = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_push($push_state, $message1, '', $tag1);
        
        list($decrypted1, $tag_out1) = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_pull($pull_state, $encrypted1);
        $this->assertSame($message1, $decrypted1);
        $this->assertSame($tag1, $tag_out1);

        // 4. Second message with re-key
        $message2 = 'This is the second message, with a rekey.';
        $tag2 = ParagonIE_Sodium_Compat::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY;
        $encrypted2 = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_push($push_state, $message2, '', $tag2);
        
        list($decrypted2, $tag_out2) = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_pull($pull_state, $encrypted2);
        $this->assertSame($message2, $decrypted2);
        $this->assertSame($tag2, $tag_out2);

        // 5. Final message
        $message3 = 'This is the final message.';
        $tag3 = ParagonIE_Sodium_Compat::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL;
        $encrypted3 = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_push($push_state, $message3, '', $tag3);

        list($decrypted3, $tag_out3) = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_pull($pull_state, $encrypted3);
        $this->assertSame($message3, $decrypted3);
        $this->assertSame($tag3, $tag_out3);
    }

    public function testPullFailure(): void
    {
        // 1. Key Generation
        $key = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_keygen();

        // 2. Initialization
        list($push_state, $header) = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_init_push($key);
        $pull_state = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_init_pull($header, $key);

        // 3. Create a valid message
        $message1 = 'This is the first message.';
        $tag1 = ParagonIE_Sodium_Compat::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH;
        $encrypted1 = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_push($push_state, $message1, '', $tag1);

        // 4. Tamper with the ciphertext
        $tampered = $encrypted1;
        $tampered[0] = \chr(\ord($tampered[0]) ^ 0xff); // Flip the first byte

        // 5. Assert that pull returns false
        $this->assertFalse(
            ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_pull($pull_state, $tampered)
        );
    }
}
