<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class WycheproofTest extends TestCase
{
    private string $dir;

    /**
     * @before
     */
    #[Before]
    public function before(): void
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
        $this->dir = dirname(__FILE__) . '/wycheproof/';
    }

    /**
     * @throws Exception
     */
    public function testChaCha20Poly1305(): void
    {
        if (empty($this->dir)) {
            $this->before();
        }
        $this->mainTestingLoop('chacha20_poly1305_test.json', 'doChaCha20Poly1305Test', false);
    }

    /**
     * @throws Exception
     */
    public function testXChaCha20Poly1305(): void
    {
        if (empty($this->dir)) {
            $this->before();
        }
        $this->mainTestingLoop('xchacha20_poly1305_test.json', 'doXChaCha20Poly1305Test', false);
    }

    /**
     * @throws Exception
     */
    public function testSipHash24(): void
    {
        if (empty($this->dir)) {
            $this->before();
        }
        $this->mainTestingLoop('siphash_2_4_test.json', 'doSipHash24Test', false);
    }

    /**
     * @throws Exception
     */
    public function testX25519(): void
    {
        if (!defined('DO_PEDANTIC_TEST')) {
            $this->markTestSkipped('Skipping Wycheproof Tests. Use DO_PEDANTIC_TEST to enable.');
        }
        if (empty($this->dir)) {
            $this->before();
        }
        $this->mainTestingLoop('x25519_test.json', 'doX25519Test', false);
    }

    /**
     * @throws Exception
     */
    public function testEd25519(): void
    {
        if (!defined('DO_PEDANTIC_TEST')) {
            $this->markTestSkipped('Skipping Wycheproof Tests. Use DO_PEDANTIC_TEST to enable.');
        }
        if (empty($this->dir)) {
            $this->before();
        }
        $this->mainTestingLoop('ed25519_test.json', 'doEd25519Test', false);
    }

    /**
     * @param $filename
     * @param $method
     *
     * @throws Exception
     */
    public function mainTestingLoop($filename, $method, $progress = false): void
    {
        $total = 0;
        $document = $this->getJson($this->dir . $filename);
        if ($progress) {
            $groupCount = count($document['testGroups']);
            $groupId = 1;
        }
        foreach ($document['testGroups'] as $testGroup) {
            if ($progress) {
                $testCount = count($testGroup['tests']);
                $testId = 1;
            }
            // Inject testGroup data
            $extra = [];
            if (array_key_exists('publicKey', $testGroup)) {
                $extra['publicKey'] = $testGroup['publicKey']['pk'];
            }
            foreach ($testGroup['tests'] as $test) {
                ++$total;
                if ($progress) {
                    echo "[Group {$groupId} : Test {$testId}]", PHP_EOL;
                }
                $message = "{$document['algorithm']} :: #{$test['tcId']} - {$test['comment']}";
                $test = $test + $extra;
                try {
                    $result = call_user_func_array(array($this, $method), array($test));
                    $expected = ($test['result'] === 'valid');
                    if ($result !== $expected) {
                        call_user_func_array(array($this, $method), array($test, true));
                    }
                    $this->assertSame($result, $expected, $message);
                } catch (Exception $ex) {
                    if ($test['result'] === 'valid') {
                        $this->fail("{$message} (" . $ex->getMessage() . ")");
                    }
                }
                if ($progress) {
                    ++$groupId;
                }
            }
            if ($progress) {
                ++$groupId;
            }
        }
    }

    /**
     * @param array $test
     * @param bool $verbose
     * @return bool
     * @throws SodiumException
     */
    public function doChaCha20Poly1305Test(array $test, $verbose = false)
    {
        $key = ParagonIE_Sodium_Compat::hex2bin($test['key']);
        $iv = ParagonIE_Sodium_Compat::hex2bin($test['iv']);
        $aad = ParagonIE_Sodium_Compat::hex2bin($test['aad']);
        $msg = ParagonIE_Sodium_Compat::hex2bin($test['msg']);
        $ct = ParagonIE_Sodium_Compat::hex2bin($test['ct']);
        $tag = ParagonIE_Sodium_Compat::hex2bin($test['tag']);

        $encrypted = ParagonIE_Sodium_Compat::crypto_aead_chacha20poly1305_ietf_encrypt(
            $msg,
            $aad,
            $iv,
            $key
        );
        if ($verbose && !ParagonIE_Sodium_Core_Util::hashEquals($ct . $tag, $encrypted)) {
            echo 'Difference in Wycheproof test vectors:', PHP_EOL;
            echo '- ', ParagonIE_Sodium_Core_Util::bin2hex($ct . $tag), PHP_EOL;
            echo '+ ', ParagonIE_Sodium_Core_Util::bin2hex($encrypted), PHP_EOL;
        }
        return ParagonIE_Sodium_Core_Util::hashEquals($ct . $tag, $encrypted);
    }

    /**
     * @param array $test
     * @param bool $verbose
     * @return bool
     * @throws SodiumException
     */
    public function doXChaCha20Poly1305Test(array $test, $verbose = false)
    {
        $key = ParagonIE_Sodium_Compat::hex2bin($test['key']);
        $iv = ParagonIE_Sodium_Compat::hex2bin($test['iv']);
        $aad = ParagonIE_Sodium_Compat::hex2bin($test['aad']);
        $msg = ParagonIE_Sodium_Compat::hex2bin($test['msg']);
        $ct = ParagonIE_Sodium_Compat::hex2bin($test['ct']);
        $tag = ParagonIE_Sodium_Compat::hex2bin($test['tag']);

        $encrypted = ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_ietf_encrypt(
            $msg,
            $aad,
            $iv,
            $key
        );
        if ($verbose && !ParagonIE_Sodium_Core_Util::hashEquals($ct . $tag, $encrypted)) {
            echo 'Difference in Wycheproof test vectors:', PHP_EOL;
            echo '- ', ParagonIE_Sodium_Core_Util::bin2hex($ct . $tag), PHP_EOL;
            echo '+ ', ParagonIE_Sodium_Core_Util::bin2hex($encrypted), PHP_EOL;
        }
        return ParagonIE_Sodium_Core_Util::hashEquals($ct . $tag, $encrypted);
    }

    /**
     * @param array $test
     * @param bool $verbose
     * @return bool
     * @throws SodiumException
     */
    public function doX25519Test(array $test, $verbose = false)
    {
        $private = ParagonIE_Sodium_Compat::hex2bin($test['private']);
        $public = ParagonIE_Sodium_Compat::hex2bin($test['public']);
        $shared = ParagonIE_Sodium_Compat::hex2bin($test['shared']);

        $scalarmult = ParagonIE_Sodium_Compat::crypto_scalarmult($private, $public);
        if ($verbose &&!ParagonIE_Sodium_Core_Util::hashEquals($shared, $scalarmult)) {
            echo 'Difference in Wycheproof test vectors:', PHP_EOL;
            echo '- ', ParagonIE_Sodium_Core_Util::bin2hex($shared), PHP_EOL;
            echo '+ ', ParagonIE_Sodium_Core_Util::bin2hex($scalarmult), PHP_EOL;
        }
        return ParagonIE_Sodium_Core_Util::hashEquals($shared, $scalarmult);
    }

    /**
     * @param array $test
     * @param bool $verbose
     * @return bool
     * @throws SodiumException
     */
    public function doEd25519Test(array $test, $verbose = false)
    {
        $msg = ParagonIE_Sodium_Compat::hex2bin($test['msg']);
        $sig = ParagonIE_Sodium_Compat::hex2bin($test['sig']);
        $pk = ParagonIE_Sodium_Compat::hex2bin($test['publicKey']);
        return ParagonIE_Sodium_Compat::crypto_sign_verify_detached($sig, $msg, $pk);
    }

    /**
     * @param array $test
     * @param bool $verbose
     * @return bool
     * @throws SodiumException
     */
    public function doSipHash24Test(array $test, $verbose = false)
    {
        $key = ParagonIE_Sodium_Compat::hex2bin($test['key']);
        $msg = ParagonIE_Sodium_Compat::hex2bin($test['msg']);
        $tag = ParagonIE_Sodium_Compat::hex2bin($test['tag']);
        $result = ParagonIE_Sodium_Compat::crypto_shorthash($msg, $key);
        if ($verbose && !ParagonIE_Sodium_Core_Util::hashEquals($tag, $result)) {
            echo 'Difference in Wycheproof test vectors:', PHP_EOL;
            echo '- ', ParagonIE_Sodium_Core_Util::bin2hex($tag), PHP_EOL;
            echo '+ ', ParagonIE_Sodium_Core_Util::bin2hex($result), PHP_EOL;
        }
        return ParagonIE_Sodium_Core_Util::hashEquals($tag, $result);
    }

    /**
     * @param string $file
     *
     * @return mixed
     * @throws Exception
     */
    public function getJson($file = '')
    {
        if (!is_readable($file)) {
            throw new Exception('Could not read file');
        }
        $contents = file_get_contents($file);
        if (!is_string($contents)) {
            throw new Exception('Could not read file');
        }
        $decoded = json_decode($contents, true);
        if (!is_array($decoded)) {
            throw new Exception('Error decoding JSON blob');
        }
        return $decoded;
    }
}
