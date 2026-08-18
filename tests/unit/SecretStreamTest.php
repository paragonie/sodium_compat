<?php

/**
 * Class SecretStreamTest
 */
class SecretStreamTest extends PHPUnit_Framework_TestCase
{
    /**
     * @throws Exception
     */
    public function testStateSerialization()
    {
        $key = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_keygen();
        $nonce = random_bytes(12);
        $state = new ParagonIE_Sodium_Core_SecretStream_State($key, $nonce);
        $toString = $state->toString();
        $fromString = ParagonIE_Sodium_Core_SecretStream_State::fromString($toString);

        $this->assertSame(
            $state->getNonce(),
            $fromString->getNonce()
        );
        $this->assertSame(
            $state->getCounter(),
            $fromString->getCounter()
        );
        $this->assertSame(
            $state->getKey(),
            $fromString->getKey()
        );
    }

    public function testRekeyUsesFullCounterWidth()
    {
        $classes = array(
            'ParagonIE_Sodium_Core_SecretStream_State',
            'ParagonIE_Sodium_Core32_SecretStream_State'
        );
        foreach ($classes as $class) {
            $state = new $class(str_repeat("\0", 32));
            $counter = new ReflectionProperty($class, 'counter');
            if (PHP_VERSION_ID < 80500) {
                $counter->setAccessible(true);
            }
            $counter->setValue($state, 0xffffffff - 1);
            $this->assertFalse($state->needsRekey());
            $state->incrementCounter();
            $this->assertFalse($state->needsRekey());
            $state->incrementCounter();
            $this->assertTrue($state->needsRekey());
        }
    }

    /**
     * @throws Exception
     */
    public function testSecretStreamMain()
    {
        $key = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_keygen();
        list($pushState, $header) = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_init_push($key);
        $pullState = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_init_pull($header, $key);
        $this->assertEquals(bin2hex($pushState), bin2hex($pullState));

        $aad = '';
        for ($i = 0; $i < 20; ++$i) {
            $msg = random_bytes(1024);
            if ($i === 10) {
                $aad = 'test';
            }
            $encrypt = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_push($pushState, $msg, $aad);
            list($decrypt, $tag) = ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_pull($pullState, $encrypt, $aad);
            $this->assertEquals(bin2hex($pushState), bin2hex($pullState));
            $this->assertEquals(bin2hex($msg), bin2hex($decrypt));
            $this->assertEquals(0, $tag);
        }
        ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_rekey($pushState);
        ParagonIE_Sodium_Compat::crypto_secretstream_xchacha20poly1305_rekey($pullState);
        $this->assertEquals(bin2hex($pushState), bin2hex($pullState));
    }
}
