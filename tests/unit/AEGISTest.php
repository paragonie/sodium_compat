<?php

use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversClass(ParagonIE_Sodium_Core_AEGIS128L::class)]
#[CoversClass(ParagonIE_Sodium_Core_AEGIS256::class)]
#[CoversClass(ParagonIE_Sodium_Core_AEGIS_State128L::class)]
#[CoversClass(ParagonIE_Sodium_Core_AEGIS_State256::class)]
class AEGISTest extends TestCase
{
    /**
     * @before
     */
    #[Before]
    public function before(): void
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    public function testAegis128lUpdate(): void
    {
        $state = ParagonIE_Sodium_Core_AEGIS_State128L::initForUnitTests(array(
            ParagonIE_Sodium_Core_Util::hex2bin('9b7e60b24cc873ea894ecc07911049a3'),
            ParagonIE_Sodium_Core_Util::hex2bin('330be08f35300faa2ebf9a7b0d274658'),
            ParagonIE_Sodium_Core_Util::hex2bin('7bbd5bd2b049f7b9b515cf26fbe7756c'),
            ParagonIE_Sodium_Core_Util::hex2bin('c35a00f55ea86c3886ec5e928f87db18'),
            ParagonIE_Sodium_Core_Util::hex2bin('9ebccafce87cab446396c4334592c91f'),
            ParagonIE_Sodium_Core_Util::hex2bin('58d83e31f256371e60fc6bb257114601'),
            ParagonIE_Sodium_Core_Util::hex2bin('1639b56ea322c88568a176585bc915de'),
            ParagonIE_Sodium_Core_Util::hex2bin('640818ffb57dc0fbc2e72ae93457e39a')
        ));
        $m0 = ParagonIE_Sodium_Core_Util::hex2bin('033e6975b94816879e42917650955aa0');
        $m1 = ParagonIE_Sodium_Core_Util::hex2bin('033e6975b94816879e42917650955aa0');
        $state->update($m0, $m1);
        $s = $state->getState();
        $expected = array(
            ParagonIE_Sodium_Core_Util::hex2bin('596ab773e4433ca0127c73f60536769d'),
            ParagonIE_Sodium_Core_Util::hex2bin('790394041a3d26ab697bde865014652d'),
            ParagonIE_Sodium_Core_Util::hex2bin('38cf49e4b65248acd533041b64dd0611'),
            ParagonIE_Sodium_Core_Util::hex2bin('16d8e58748f437bfff1797f780337cee'),
            ParagonIE_Sodium_Core_Util::hex2bin('69761320f7dd738b281cc9f335ac2f5a'),
            ParagonIE_Sodium_Core_Util::hex2bin('a21746bb193a569e331e1aa985d0d729'),
            ParagonIE_Sodium_Core_Util::hex2bin('09d714e6fcf9177a8ed1cde7e3d259a6'),
            ParagonIE_Sodium_Core_Util::hex2bin('61279ba73167f0ab76f0a11bf203bdff')
        );
        $this->assertSame($s, $expected);
    }

    public function testAegis256lUpdate(): void
    {
        $state = ParagonIE_Sodium_Core_AEGIS_State256::initForUnitTests(array(
            ParagonIE_Sodium_Core_Util::hex2bin('1fa1207ed76c86f2c4bb40e8b395b43e'),
            ParagonIE_Sodium_Core_Util::hex2bin('b44c375e6c1e1978db64bcd12e9e332f'),
            ParagonIE_Sodium_Core_Util::hex2bin('0dab84bfa9f0226432ff630f233d4e5b'),
            ParagonIE_Sodium_Core_Util::hex2bin('d7ef65c9b93e8ee60c75161407b066e7'),
            ParagonIE_Sodium_Core_Util::hex2bin('a760bb3da073fbd92bdc24734b1f56fb'),
            ParagonIE_Sodium_Core_Util::hex2bin('a828a18d6a964497ac6e7e53c5f55c73')
        ));
        $m = ParagonIE_Sodium_Core_Util::hex2bin('b165617ed04ab738afb2612c6d18a1ec');
        $state->update($m);
        $s = $state->getState();
        $expected = array(
            ParagonIE_Sodium_Core_Util::hex2bin('e6bc643bae82dfa3d991b1b323839dcd'),
            ParagonIE_Sodium_Core_Util::hex2bin('648578232ba0f2f0a3677f617dc052c3'),
            ParagonIE_Sodium_Core_Util::hex2bin('ea788e0e572044a46059212dd007a789'),
            ParagonIE_Sodium_Core_Util::hex2bin('2f1498ae19b80da13fba698f088a8590'),
            ParagonIE_Sodium_Core_Util::hex2bin('a54c2ee95e8c2a2c3dae2ec743ae6b86'),
            ParagonIE_Sodium_Core_Util::hex2bin('a3240fceb68e32d5d114df1b5363ab67')
        );
        $this->assertSame($s, $expected);
    }

    /**
     * @return array[]
     *
     * name, key, nonce, tag, ciphertext, plaintext, aad, expect_fail?
     */
    public static function aegis128lVectors(): array
    {
        return array(
            array(
                'AEGIS-128L test vector 1',
                '10010000000000000000000000000000',
                '10000200000000000000000000000000',
                '25835bfbb21632176cf03840687cb968cace4617af1bd0f7d064c639a5c79ee4',
                'c1c0e58bd913006feba00f4b3cc3594e',
                '00000000000000000000000000000000',
                '',
                false
            ),
            array(
                'AEGIS-128L test vector 2',
                '10010000000000000000000000000000',
                '10000200000000000000000000000000',
                '1360dc9db8ae42455f6e5b6a9d488ea4f2184c4e12120249335c4ee84bafe25d',
                '',
                '',
                '',
                false
            ),
            array(
                'AEGIS-128L test vector 3',
                '10010000000000000000000000000000',
                '10000200000000000000000000000000',
                '022cb796fe7e0ae1197525ff67e309484cfbab6528ddef89f17d74ef8ecd82b3',
                '79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84',
                '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
                '0001020304050607',
                false
            ),
            array(
                'AEGIS-128L test vector 4',
                '10010000000000000000000000000000',
                '10000200000000000000000000000000',
                '86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac',
                '79d94593d8c2119d7e8fd9b8fc77',
                '000102030405060708090a0b0c0d',
                '0001020304050607',
                false
            ),
            array(
                'AEGIS-128L test vector 5',
                '10010000000000000000000000000000',
                '10000200000000000000000000000000',
                'b91e2947a33da8bee89b6794e647baf0fc835ff574aca3fc27c33be0db2aff98',
                'b31052ad1cca4e291abcf2df3502e6bdb1bfd6db36798be3607b1f94d34478aa7ede7f7a990fec10',
                '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637',
                '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829',
                false
            ),
            array(
                'AEGIS-128L test vector 6',
                '10000200000000000000000000000000',
                '10010000000000000000000000000000',
                '86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac',
                '79d94593d8c2119d7e8fd9b8fc77',
                '',
                '0001020304050607',
                true
            ),
            array(
                'AEGIS-128L test vector 7',
                '10010000000000000000000000000000',
                '10000200000000000000000000000000',
                '86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac',
                '79d94593d8c2119d7e8fd9b8fc78',
                '',
                '0001020304050607',
                true
            ),
            array(
                'AEGIS-128L test vector 8',
                '10010000000000000000000000000000',
                '10000200000000000000000000000000',
                '86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac',
                '79d94593d8c2119d7e8fd9b8fc77',
                '',
                '0001020304050608',
                true
            ),
            array(
                'AEGIS-128L test vector 9',
                '10010000000000000000000000000000',
                '10000200000000000000000000000000',
                '86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ad',
                '79d94593d8c2119d7e8fd9b8fc77',
                '',
                '0001020304050607',
                true
            ),
        );
    }

    /**
     * @return array[]
     *
     * name, key, nonce, tag, ciphertext, plaintext, aad, expect_fail?
     */
    public static function aegis256Vectors(): array
    {
        return array(
            array(
                'AEGIS-256 test vector 1',
                '1001000000000000000000000000000000000000000000000000000000000000',
                '1000020000000000000000000000000000000000000000000000000000000000',
                '1181a1d18091082bf0266f66297d167d2e68b845f61a3b0527d31fc7b7b89f13',
                '754fc3d8c973246dcc6d741412a4b236',
                '00000000000000000000000000000000',
                '',
                false
            ),
            array(
                'AEGIS-256 test vector 2',
                '1001000000000000000000000000000000000000000000000000000000000000',
                '1000020000000000000000000000000000000000000000000000000000000000',
                '6a348c930adbd654896e1666aad67de989ea75ebaa2b82fb588977b1ffec864a',
                '',
                '',
                '',
                false
            ),
            array(
                'AEGIS-256 test vector 3',
                '1001000000000000000000000000000000000000000000000000000000000000',
                '1000020000000000000000000000000000000000000000000000000000000000',
                'b7d28d0c3c0ebd409fd22b44160503073a547412da0854bfb9723020dab8da1a',
                'f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711',
                '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
                '0001020304050607',
                false
            ),
            array(
                'AEGIS-256 test vector 4',
                '1001000000000000000000000000000000000000000000000000000000000000',
                '1000020000000000000000000000000000000000000000000000000000000000',
                '8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9',
                'f373079ed84b2709faee37358458',
                '000102030405060708090a0b0c0d',
                '0001020304050607',
                false
            ),
            array(
                'AEGIS-256 test vector 5',
                '1001000000000000000000000000000000000000000000000000000000000000',
                '1000020000000000000000000000000000000000000000000000000000000000',
                'a3aca270c006094d71c20e6910b5161c0826df233d08919a566ec2c05990f734',
                '57754a7d09963e7c787583a2e7b859bb24fa1e04d49fd550b2511a358e3bca252a9b1b8b30cc4a67',
                '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637',
                '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829',
                false
            ),
            array(
                'AEGIS-256 test vector 6',
                '1000020000000000000000000000000000000000000000000000000000000000',
                '1001000000000000000000000000000000000000000000000000000000000000',
                '8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9',
                'f373079ed84b2709faee37358458',
                '',
                '0001020304050607',
                true
            ),
            array(
                'AEGIS-256 test vector 7',
                '1001000000000000000000000000000000000000000000000000000000000000',
                '1000020000000000000000000000000000000000000000000000000000000000',
                '8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9',
                'f373079ed84b2709faee37358459',
                '',
                '0001020304050607',
                true
            ),
            array(
                'AEGIS-256 test vector 8',
                '1001000000000000000000000000000000000000000000000000000000000000',
                '1000020000000000000000000000000000000000000000000000000000000000',
                '8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9',
                'f373079ed84b2709faee37358458',
                '',
                '0001020304050608',
                true
            ),
            array(
                'AEGIS-256 test vector 9',
                '1001000000000000000000000000000000000000000000000000000000000000',
                '1000020000000000000000000000000000000000000000000000000000000000',
                '8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2da',
                'f373079ed84b2709faee37358458',
                '',
                '0001020304050607',
                true
            )
        );
    }

    /**
     * @dataProvider aegis128lVectors
     * @throws SodiumException
     */
    #[DataProvider("aegis128lVectors")]
    public function testAegis128lVectors(
        string $name,
        string $key_hex,
        string $nonce_hex,
        string $expected_tag_hex,
        string $expected_ct_hex,
        string $msg_hex = '',
        string $ad_hex = '',
        bool $expect_fail = false
    ): void {
        $key = ParagonIE_Sodium_Core_Util::hex2bin($key_hex);
        $nonce = ParagonIE_Sodium_Core_Util::hex2bin($nonce_hex);
        $expTag = ParagonIE_Sodium_Core_Util::hex2bin($expected_tag_hex);
        $expCt = ParagonIE_Sodium_Core_Util::hex2bin($expected_ct_hex);
        $ad = ParagonIE_Sodium_Core_Util::hex2bin($ad_hex);
        if ($expect_fail) {
            $failed = false;
            try {
                ParagonIE_Sodium_Core_AEGIS128L::decrypt($expCt, $expTag, $ad, $key, $nonce);
            } catch (SodiumException $ex) {
                $failed = true;
            }
            $this->assertTrue($failed, 'Expected decryption to fail but it did not');
            return;
        }
        $msg = ParagonIE_Sodium_Core_Util::hex2bin($msg_hex);
        list($ct, $tag) = ParagonIE_Sodium_Core_AEGIS128L::encrypt($msg, $ad, $key, $nonce);

        $this->assertSame(
            ParagonIE_Sodium_Core_Util::bin2hex($expCt),
            ParagonIE_Sodium_Core_Util::bin2hex($ct),
            $name
        );
        $this->assertSame(
            ParagonIE_Sodium_Core_Util::bin2hex($expTag),
            ParagonIE_Sodium_Core_Util::bin2hex($tag),
            $name
        );
        $this->assertSame($expCt, $ct, $name);
        $this->assertSame($expTag, $tag, $name);
        $got_pt = ParagonIE_Sodium_Core_AEGIS128L::decrypt($expCt, $expTag, $ad, $key, $nonce);
        $this->assertSame(
            ParagonIE_Sodium_Core_Util::bin2hex($got_pt),
            $msg_hex,
            $name
        );
        $this->assertSame($got_pt, $msg, $name);
    }

    /**
     * @dataProvider aegis256Vectors
     * @throws SodiumException
     */
    #[DataProvider("aegis256Vectors")]
    public function testAegis256Vectors(
        string $name,
        string $key_hex,
        string $nonce_hex,
        string $expected_tag_hex,
        string $expected_ct_hex,
        string $msg_hex = '',
        string $ad_hex = '',
        bool $expect_fail = false
    ): void {
        $key = ParagonIE_Sodium_Core_Util::hex2bin($key_hex);
        $nonce = ParagonIE_Sodium_Core_Util::hex2bin($nonce_hex);
        $expTag = ParagonIE_Sodium_Core_Util::hex2bin($expected_tag_hex);
        $expCt = ParagonIE_Sodium_Core_Util::hex2bin($expected_ct_hex);
        $ad = ParagonIE_Sodium_Core_Util::hex2bin($ad_hex);
        if ($expect_fail) {
            $failed = false;
            try {
                ParagonIE_Sodium_Core_AEGIS256::decrypt($expCt, $expTag, $ad, $key, $nonce);
            } catch (SodiumException $ex) {
                $failed = true;
            }
            $this->assertTrue($failed, 'Expected decryption to fail but it did not');
            return;
        }
        $msg = ParagonIE_Sodium_Core_Util::hex2bin($msg_hex);
        list($ct, $tag) = ParagonIE_Sodium_Core_AEGIS256::encrypt($msg, $ad, $key, $nonce);

        $this->assertSame(
            ParagonIE_Sodium_Core_Util::bin2hex($expCt),
            ParagonIE_Sodium_Core_Util::bin2hex($ct),
            $name
        );
        $this->assertSame(
            ParagonIE_Sodium_Core_Util::bin2hex($expTag),
            ParagonIE_Sodium_Core_Util::bin2hex($tag),
            $name
        );
        $this->assertSame($expCt, $ct, $name);
        $this->assertSame($expTag, $tag, $name);
        $got_pt = ParagonIE_Sodium_Core_AEGIS256::decrypt($expCt, $expTag, $ad, $key, $nonce);
        $this->assertSame(
            ParagonIE_Sodium_Core_Util::bin2hex($got_pt),
            $msg_hex,
            $name
        );
        $this->assertSame($got_pt, $msg, $name);
    }

    public function testPublicAegis128l(): void
    {
        $msg = ParagonIE_Sodium_Compat::randombytes_buf(ParagonIE_Sodium_Compat::randombytes_uniform(999) + 1);
        $nonce = ParagonIE_Sodium_Compat::randombytes_buf(ParagonIE_Sodium_Compat::CRYPTO_AEAD_AEGIS128L_NPUBBYTES);
        $ad = ParagonIE_Sodium_Compat::randombytes_buf(ParagonIE_Sodium_Compat::randombytes_uniform(999) + 1);
        $key = ParagonIE_Sodium_Compat::crypto_aead_aegis128l_keygen();
        $ciphertext = ParagonIE_Sodium_Compat::crypto_aead_aegis128l_encrypt($msg, $ad, $nonce, $key);
        $msg2 = ParagonIE_Sodium_Compat::crypto_aead_aegis128l_decrypt($ciphertext, $ad, $nonce, $key);
        $this->assertSame($msg, $msg2);
    }

    public function testPublicAegis256(): void
    {
        $msg = ParagonIE_Sodium_Compat::randombytes_buf(ParagonIE_Sodium_Compat::randombytes_uniform(999) + 1);
        $nonce = ParagonIE_Sodium_Compat::randombytes_buf(ParagonIE_Sodium_Compat::CRYPTO_AEAD_AEGIS256_NPUBBYTES);
        $ad = ParagonIE_Sodium_Compat::randombytes_buf(ParagonIE_Sodium_Compat::randombytes_uniform(999) + 1);
        $key = ParagonIE_Sodium_Compat::crypto_aead_aegis256_keygen();
        $ciphertext = ParagonIE_Sodium_Compat::crypto_aead_aegis256_encrypt($msg, $ad, $nonce, $key);
        $msg2 = ParagonIE_Sodium_Compat::crypto_aead_aegis256_decrypt($ciphertext, $ad, $nonce, $key);
        $this->assertSame($msg, $msg2);
    }

    public function testEmptyState(): void
    {
        $state = (new ParagonIE_Sodium_Core_AEGIS_State128L())->getState();
        $this->assertSame($state, ['', '', '', '', '', '', '', '']);
        $state = (new ParagonIE_Sodium_Core_AEGIS_State256())->getState();
        $this->assertSame($state, ['', '', '', '', '', '']);
    }

    /**
     * @return void
     * @throws SodiumException
     */
    public function testEmptyInputsAegis128l(): void
    {
        $key = ParagonIE_Sodium_Compat::crypto_aead_aegis128l_keygen();
        $nonce = str_repeat("\0",ParagonIE_Sodium_Compat::CRYPTO_AEAD_AEGIS128L_NPUBBYTES);
        $ad = '';
        $encrypted = ParagonIE_Sodium_Compat::crypto_aead_aegis128l_encrypt('', $ad, $nonce, $key);
        $this->assertNotSame('', $encrypted, 'Authentication tag expected');
        $this->assertSame(
            '',
            ParagonIE_Sodium_Compat::crypto_aead_aegis128l_decrypt($encrypted, $ad, $nonce, $key)
        );
    }

    /**
     * @return void
     * @throws SodiumException
     */
    public function testEmptyInputsAegis256(): void
    {
        $key = ParagonIE_Sodium_Compat::crypto_aead_aegis256_keygen();
        $nonce = str_repeat("\0",ParagonIE_Sodium_Compat::CRYPTO_AEAD_AEGIS256_NPUBBYTES);
        $ad = '';
        $encrypted = ParagonIE_Sodium_Compat::crypto_aead_aegis256_encrypt('', $ad, $nonce, $key);
        $this->assertNotSame('', $encrypted, 'Authentication tag expected');
        $this->assertSame(
            '',
            ParagonIE_Sodium_Compat::crypto_aead_aegis256_decrypt($encrypted, $ad, $nonce, $key)
        );
    }

    /**
     * @throws SodiumException
     */
    public function testAegisInvalidInputs(): void
    {
        // AEGIS-128L
        $key = ParagonIE_Sodium_Compat::crypto_aead_aegis128l_keygen();
        $nonce = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_AEAD_AEGIS128L_NPUBBYTES);
        $msg = 'test';
        $ad = 'test';

        try {
            ParagonIE_Sodium_Compat::crypto_aead_aegis128l_encrypt($msg, $ad, substr($nonce, 1), $key);
            $this->fail('Invalid nonce length');
        } catch (Exception $ex) {
            $this->assertInstanceOf(SodiumException::class, $ex);
        }
        try {
            ParagonIE_Sodium_Compat::crypto_aead_aegis128l_encrypt($msg, $ad, $nonce, substr($key, 1));
            $this->fail('Invalid key length');
        } catch (Exception $ex) {
            $this->assertInstanceOf(SodiumException::class, $ex);
        }

        $ciphertext = ParagonIE_Sodium_Compat::crypto_aead_aegis128l_encrypt($msg, $ad, $nonce, $key);
        try {
            ParagonIE_Sodium_Compat::crypto_aead_aegis128l_decrypt(substr($ciphertext, 1), $ad, $nonce, $key);
            $this->fail('Ciphertext too short');
        } catch (Exception $ex) {
            $this->assertInstanceOf(SodiumException::class, $ex);
        }

        // AEGIS-256
        $key256 = ParagonIE_Sodium_Compat::crypto_aead_aegis256_keygen();
        $nonce256 = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_AEAD_AEGIS256_NPUBBYTES);

        try {
            ParagonIE_Sodium_Compat::crypto_aead_aegis256_encrypt($msg, $ad, substr($nonce256, 1), $key256);
            $this->fail('Invalid nonce length');
        } catch (Exception $ex) {
            $this->assertInstanceOf(SodiumException::class, $ex);
        }
        try {
            ParagonIE_Sodium_Compat::crypto_aead_aegis256_encrypt($msg, $ad, $nonce256, substr($key256, 1));
            $this->fail('Invalid key length');
        } catch (Exception $ex) {
            $this->assertInstanceOf(SodiumException::class, $ex);
        }

        $ciphertext256 = ParagonIE_Sodium_Compat::crypto_aead_aegis256_encrypt($msg, $ad, $nonce256, $key256);
        try {
            ParagonIE_Sodium_Compat::crypto_aead_aegis256_decrypt(substr($ciphertext256, 1), $ad, $nonce256, $key256);
            $this->fail('Ciphertext too short');
        } catch (Exception $ex) {
            $this->assertInstanceOf(SodiumException::class, $ex);
        }

        $this->assertSame(
            ParagonIE_Sodium_Compat::CRYPTO_AEAD_AEGIS128L_KEYBYTES,
            strlen($key)
        );
        $this->assertSame(
            ParagonIE_Sodium_Compat::CRYPTO_AEAD_AEGIS256_KEYBYTES,
            strlen($key256)
        );
    }

    public function testAegis128LDecryptBadNonce(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Nonce must be CRYPTO_AEAD_AEGIS128L_NPUBBYTES long');

        $key = str_repeat("\0", 16);
        $nonce = str_repeat("\0", 15);
        $ciphertext = str_repeat("\0", 32);
        ParagonIE_Sodium_Compat::crypto_aead_aegis128l_decrypt($ciphertext, '', $nonce, $key);
    }
    public function testAegis128LDecryptSuperfluousNonce(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Nonce must be CRYPTO_AEAD_AEGIS128L_NPUBBYTES long');

        $key = str_repeat("\0", 16);
        $nonce = str_repeat("\0", 64);
        $ciphertext = str_repeat("\0", 32);
        ParagonIE_Sodium_Compat::crypto_aead_aegis128l_decrypt($ciphertext, '', $nonce, $key);
    }

    public function testAegis128LDecryptBadKey(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Key must be CRYPTO_AEAD_AEGIS128L_KEYBYTES long');

        $key = str_repeat("\0", 15);
        $nonce = str_repeat("\0", 16);
        $ciphertext = str_repeat("\0", 32);
        ParagonIE_Sodium_Compat::crypto_aead_aegis128l_decrypt($ciphertext, '', $nonce, $key);
    }

    public function testAegis256DecryptBadNonce(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Nonce must be CRYPTO_AEAD_AEGIS256_NPUBBYTES long');

        $key = str_repeat("\0", 32);
        $nonce = str_repeat("\0", 31);
        $ciphertext = str_repeat("\0", 32);
        ParagonIE_Sodium_Compat::crypto_aead_aegis256_decrypt($ciphertext, '', $nonce, $key);
    }

    public function testAegis256DecryptSuperfluousNonce(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Nonce must be CRYPTO_AEAD_AEGIS256_NPUBBYTES long');

        $key = str_repeat("\0", 32);
        $nonce = str_repeat("\0", 64);
        $ciphertext = str_repeat("\0", 32);
        ParagonIE_Sodium_Compat::crypto_aead_aegis256_decrypt($ciphertext, '', $nonce, $key);
    }

    public function testAegis256DecryptBadKey(): void
    {
        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Key must be CRYPTO_AEAD_AEGIS256_KEYBYTES long');

        $key = str_repeat("\0", 31);
        $nonce = str_repeat("\0", 32);
        $ciphertext = str_repeat("\0", 32);
        ParagonIE_Sodium_Compat::crypto_aead_aegis256_decrypt($ciphertext, '', $nonce, $key);
    }

    public function testAegis128LDecryptShortCiphertext(): void
    {
        $this->expectException(SodiumException::class);

        $key = str_repeat("\0", 33);
        $nonce = str_repeat("\0", 32);
        ParagonIE_Sodium_Compat::crypto_aead_aegis128l_decrypt('', '', $nonce, $key);
    }

    public function testAegis256DecryptShortCiphertext(): void
    {
        $this->expectException(SodiumException::class);

        $key = str_repeat("\0", 33);
        $nonce = str_repeat("\0", 32);
        ParagonIE_Sodium_Compat::crypto_aead_aegis256_decrypt('', '', $nonce, $key);
    }
}
