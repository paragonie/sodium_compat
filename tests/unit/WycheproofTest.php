<?php

class WycheproofTest extends PHPUnit_Framework_TestCase
{
    private $dir;

    public function setUp()
    {
        if (!defined('DO_PEDANTIC_TEST')) {
            $this->markTestSkipped('Skipping Wycheproof Tests. Use DO_PEDANTIC_TEST to enable.');
        }
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
        $this->dir = dirname(__FILE__) . '/wycheproof/';
    }

    /**
     * @throws Exception
     */
    public function testChaCha20Poly1305()
    {
        if (!defined('DO_PEDANTIC_TEST')) {
            $this->markTestSkipped('Skipping Wycheproof Tests. Use DO_PEDANTIC_TEST to enable.');
        }
        $this->mainTestingLoop('chacha20_poly1305_test.json', 'doChaCha20Poly1305Test');
    }

    /**
     * @throws Exception
     */
    public function testX25519()
    {
        if (!defined('DO_PEDANTIC_TEST')) {
            $this->markTestSkipped('Skipping Wycheproof Tests. Use DO_PEDANTIC_TEST to enable.');
        }
        $this->mainTestingLoop('x25519_test.json', 'doX25519Test');
    }

    /**
     * @param $filename
     * @param $method
     *
     * @throws Exception
     */
    public function mainTestingLoop($filename, $method)
    {
        $document = $this->getJson($this->dir . $filename);
        foreach ($document['testGroups'] as $testGroup) {
            foreach ($testGroup['tests'] as $test) {
                $message = "{$document['algorithm']} :: #{$test['tcId']} - {$test['comment']}";
                try {
                    $result = call_user_func_array(array($this, $method), array($test));
                    $expected = ($test['result'] === 'valid');
                    $this->assertSame($result, $expected, $message);
                } catch (Exception $ex) {
                    if ($test['result'] === 'valid') {
                        $this->fail("{$message} (" . $ex->getMessage() . ")");
                    }
                }
            }
        }
    }

    /**
     * @param array $test
     * @return bool
     */
    public function doChaCha20Poly1305Test(array $test)
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
        return ParagonIE_Sodium_Core_Util::hashEquals($ct . $tag, $encrypted);
    }
    /**
     * @param array $test
     * @return bool
     */
    public function doX25519Test(array $test)
    {
        $private = ParagonIE_Sodium_Compat::hex2bin($test['private']);
        $public = ParagonIE_Sodium_Compat::hex2bin($test['public']);
        $shared = ParagonIE_Sodium_Compat::hex2bin($test['shared']);

        return ParagonIE_Sodium_Core_Util::hashEquals(
            $shared,
            ParagonIE_Sodium_Compat::crypto_scalarmult($private, $public)
        );
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
