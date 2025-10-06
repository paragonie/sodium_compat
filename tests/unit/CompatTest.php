<?php

use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class CompatTest extends TestCase
{
    /**
     * @before
     */
    #[Before]
    public function before(): void
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    public function testIncrement(): void
    {
        $string = "\x00\x00\x00\x00\x00\x00\x00\x00";

        ParagonIE_Sodium_Compat::increment($string);
        $this->assertSame("0100000000000000", ParagonIE_Sodium_Core_Util::bin2hex($string));

        ParagonIE_Sodium_Compat::increment($string);
        $this->assertSame("0200000000000000", ParagonIE_Sodium_Core_Util::bin2hex($string));

        $string = "\xff\xff\x01\x20";
        ParagonIE_Sodium_Compat::increment($string);
        $this->assertSame("00000220", ParagonIE_Sodium_Core_Util::bin2hex($string));

        $string = "\xff\xff\xff\xff";
        ParagonIE_Sodium_Compat::increment($string);
        $this->assertSame("00000000", ParagonIE_Sodium_Core_Util::bin2hex($string));
    }

    /**
     * @throws SodiumException
     * @throws Exception
     */
    public function testKeyExchange(): void
    {
        $alice = ParagonIE_Sodium_Compat::crypto_kx_keypair();
        $alice_pk = ParagonIE_Sodium_Compat::crypto_kx_publickey($alice);
        $bob = ParagonIE_Sodium_Compat::crypto_kx_keypair();
        $bob_pk = ParagonIE_Sodium_Compat::crypto_kx_publickey($bob);

        $alice_to_bob = ParagonIE_Sodium_Compat::crypto_kx_client_session_keys($alice, $bob_pk);
        $bob_to_alice = sodium_crypto_kx_server_session_keys($bob, $alice_pk);

        $this->assertEquals($alice_to_bob[0], $bob_to_alice[1]);
        $this->assertEquals($alice_to_bob[1], $bob_to_alice[0]);
    }

    /**
     * @throws Exception
     * @throws SodiumException
     */
    public function testSodiumPad(): void
    {
        for ($i = 0; $i < 100; ++$i) {
            $block = random_int(16, 256);
            $original = str_repeat("A", random_int(1, 1024));

            $padded = ParagonIE_Sodium_Compat::pad($original, $block);
            $unpadded = ParagonIE_Sodium_Compat::unpad($padded, $block);
            $this->assertEquals($unpadded, $original);

            $original = random_bytes(random_int(1, 1024));
            $padded = ParagonIE_Sodium_Compat::pad($original, $block);
            $unpadded = ParagonIE_Sodium_Compat::unpad($padded, $block);
            $this->assertEquals($unpadded, $original);
        }
    }

    /**
     * @throws SodiumException
     */
    public function testEd25519Keypairs(): void
    {
        $keypair = ParagonIE_Sodium_Core_Util::hex2bin(
            '73eda3c0594270f19fbed39440c15453c647987b5fd3a38164c383adfa638ebe' .
            '4bdae2767f0fc67ac0edbe3dff6b820a55e1769c740e8b9c72066828fc57434e' .
            '4bdae2767f0fc67ac0edbe3dff6b820a55e1769c740e8b9c72066828fc57434e'
        );
        $sk = ParagonIE_Sodium_Compat::crypto_sign_secretkey($keypair);
        $pk = ParagonIE_Sodium_Compat::crypto_sign_publickey($keypair);
        $this->assertSame(
            $keypair,
            ParagonIE_Sodium_Compat::crypto_sign_keypair_from_secretkey_and_publickey($sk, $pk)
        );
        try {
            ParagonIE_Sodium_Compat::crypto_sign_keypair_from_secretkey_and_publickey($pk, $sk);
            $this->fail('Order swapped should throw; it did not');
        } catch (SodiumException $ex) {
            $this->assertEquals(
                'secretkey should be SODIUM_CRYPTO_SIGN_SECRETKEYBYTES bytes',
                $ex->getMessage()
            );
        }
        try {
            ParagonIE_Sodium_Compat::crypto_sign_keypair_from_secretkey_and_publickey($sk, $sk);
            $this->fail('Invalid input accepted for public key');
        } catch (SodiumException $ex) {
            $this->assertEquals(
                'publickey should be SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES bytes',
                $ex->getMessage()
            );
        }
    }

    /**
     * @throws TypeError
     * @throws Exception
     */
    public function testBase64(): void
    {
        for ($i = 0; $i < 100; $i++) {
            $bin = $i === 0 ? '' : random_bytes($i);
            $b64 = base64_encode($bin);
            $b64_ = ParagonIE_Sodium_Compat::bin2base64($bin, SODIUM_BASE64_VARIANT_ORIGINAL);
            $this->assertEquals($b64, $b64_);
            $bin_ = ParagonIE_Sodium_Compat::base642bin($b64, SODIUM_BASE64_VARIANT_ORIGINAL);
            $this->assertEquals($bin, $bin_);

            $b64np = ParagonIE_Sodium_Compat::bin2base64($bin, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
            $this->assertEquals(rtrim($b64, '='), $b64np);
            $binnp = ParagonIE_Sodium_Compat::base642bin($b64np, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
            $this->assertEquals($bin, $binnp);

            $b64u = strtr(base64_encode($bin), '+/', '-_');
            $b64u_ = ParagonIE_Sodium_Compat::bin2base64($bin, SODIUM_BASE64_VARIANT_URLSAFE);
            $this->assertEquals($b64u, $b64u_);
            $binu_ = ParagonIE_Sodium_Compat::base642bin($b64u, SODIUM_BASE64_VARIANT_URLSAFE);
            $this->assertEquals($bin, $binu_);

            $b64np = ParagonIE_Sodium_Compat::bin2base64($bin, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
            $this->assertEquals(rtrim($b64u, '='), $b64np);
            $binnp = ParagonIE_Sodium_Compat::base642bin($b64np, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
            $this->assertEquals($bin, $binnp);
        }

        $random = random_bytes(100);
        $x = chunk_split(base64_encode($random));
        $got = ParagonIE_Sodium_Compat::base642bin($x, SODIUM_BASE64_VARIANT_ORIGINAL, "\r\n");
        $this->assertSame($random, $got);

        // Test with an empty ignore string
        try {
            ParagonIE_Sodium_Compat::base642bin($x, SODIUM_BASE64_VARIANT_ORIGINAL, '');
            $this->fail('Should have thrown an exception for invalid base64 characters.');
        } catch (SodiumException $ex) {
            // Expected
        }

        do {
            $x = random_bytes(127);
            $x64p = ParagonIE_Sodium_Compat::bin2base64($x, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } while (!str_contains($x64p, '-') && !str_contains($x64p, '_'));
        try {
            ParagonIE_Sodium_Compat::base642bin($x64p, SODIUM_BASE64_VARIANT_ORIGINAL);
            $this->fail('Should have thrown an exception for invalid base64 characters.');
        } catch (SodiumException $ex) {
            // Expected
        }

        $x64p = ParagonIE_Sodium_Compat::bin2base64($x, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
        try {
            ParagonIE_Sodium_Compat::base642bin($x64p, SODIUM_BASE64_VARIANT_URLSAFE);
            $this->fail('Should have thrown an exception for invalid base64 characters.');
        } catch (SodiumException $ex) {
            // Expected
        }
    }

    public function testCompareAndMemcmp(): void
    {
        $a = "abcdef\0";
        $b = "abcdef\0";
        $c = "abcdeg\0";
        $d = 'abcdefg';
        $e = "abcde\0\0";

        $this->assertSame(0, ParagonIE_Sodium_Compat::memcmp($a, $b));
        $this->assertNotSame(0, ParagonIE_Sodium_Compat::memcmp($a, $c));
        $this->assertNotSame(0, ParagonIE_Sodium_Compat::memcmp($a, $d));
        $this->assertNotSame(0, ParagonIE_Sodium_Compat::memcmp($a, $e));

        $this->assertSame(0, ParagonIE_Sodium_Compat::compare($a, $b));
        $this->assertSame(-1, ParagonIE_Sodium_Compat::compare($a, $c));
        $this->assertSame(1, ParagonIE_Sodium_Compat::compare($c, $a));
        $this->assertSame(-1, ParagonIE_Sodium_Compat::compare($a, $d));
        $this->assertSame(1, ParagonIE_Sodium_Compat::compare($d, $a));
    }

    /**
     * @throws SodiumException
     */
    public function testBase64Variants(): void
    {
        $bin = 'This is a test.';
        $orig = 'VGhpcyBpcyBhIHRlc3Qu';
        $origPad = 'VGhpcyBpcyBhIHRlc3Qu';
        $url = 'VGhpcyBpcyBhIHRlc3Qu';
        $urlPad = 'VGhpcyBpcyBhIHRlc3Qu';

        $this->assertSame(
            $orig,
            ParagonIE_Sodium_Compat::bin2base64($bin, ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL_NO_PADDING)
        );
        $this->assertSame(
            $origPad,
            ParagonIE_Sodium_Compat::bin2base64($bin, ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL)
        );
        $this->assertSame(
            $url,
            ParagonIE_Sodium_Compat::bin2base64($bin, ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE_NO_PADDING)
        );
        $this->assertSame(
            $urlPad,
            ParagonIE_Sodium_Compat::bin2base64($bin, ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE)
        );

        $this->assertSame(
            $bin,
            ParagonIE_Sodium_Compat::base642bin($orig, ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL_NO_PADDING)
        );
        $this->assertSame(
            $bin,
            ParagonIE_Sodium_Compat::base642bin($origPad, ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL)
        );
        $this->assertSame(
            $bin,
            ParagonIE_Sodium_Compat::base642bin($url, ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE_NO_PADDING)
        );
        $this->assertSame(
            $bin,
            ParagonIE_Sodium_Compat::base642bin($urlPad, ParagonIE_Sodium_Compat::BASE64_VARIANT_URLSAFE)
        );

        try {
            ParagonIE_Sodium_Compat::base642bin('a', -1);
            $this->fail('invalid variant');
        } catch (SodiumException $ex) {
            $this->assertSame('invalid base64 variant identifier', $ex->getMessage());
        }
        try {
            ParagonIE_Sodium_Compat::bin2base64('a', -1);
            $this->fail('invalid variant');
        } catch (SodiumException $ex) {
            $this->assertSame('invalid base64 variant identifier', $ex->getMessage());
        }

        $this->assertSame(
            '',
            ParagonIE_Sodium_Compat::base642bin('', ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL)
        );
        $this->assertSame(
            '',
            ParagonIE_Sodium_Compat::bin2base64('', ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL)
        );

        $b64 = ParagonIE_Sodium_Compat::bin2base64($bin, SODIUM_BASE64_VARIANT_ORIGINAL);
        $this->assertSame(
            $bin,
            ParagonIE_Sodium_Compat::base642bin($b64, SODIUM_BASE64_VARIANT_ORIGINAL, ' ')
        );

        try {
            ParagonIE_Sodium_Compat::base642bin('!@#$%', ParagonIE_Sodium_Compat::BASE64_VARIANT_ORIGINAL);
            $this->fail('invalid base64');
        } catch (SodiumException $ex) {
            // Expected
        }
    }

    public function testSub(): void
    {
        $a = random_bytes(32);
        $b = random_bytes(32);

        $sum = $a;
        ParagonIE_Sodium_Compat::add($sum, $b);
        ParagonIE_Sodium_Compat::sub($sum, $a);
        $this->assertSame($b, $sum);

        try {
            $c = random_bytes(32);
            ParagonIE_Sodium_Compat::sub($c, random_bytes(31));
            $this->fail('Mismatched lengths should throw an exception.');
        } catch (SodiumException $ex) {
            // Expected
        }
    }

    /**
     * @throws SodiumException
     * @throws Exception
     */
    public function testKxFunctions(): void
    {
        // Test crypto_kx_seed_keypair
        $seed = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_KX_SEEDBYTES);
        $keypair = ParagonIE_Sodium_Compat::crypto_kx_seed_keypair($seed);
        $this->assertSame(ParagonIE_Sodium_Compat::CRYPTO_KX_KEYPAIRBYTES, strlen($keypair));

        // Test crypto_kx_secretkey and crypto_kx_publickey
        $sk = ParagonIE_Sodium_Compat::crypto_kx_secretkey($keypair);
        $pk = ParagonIE_Sodium_Compat::crypto_kx_publickey($keypair);
        $this->assertSame(ParagonIE_Sodium_Compat::CRYPTO_KX_SECRETKEYBYTES, strlen($sk));
        $this->assertSame(ParagonIE_Sodium_Compat::CRYPTO_KX_PUBLICKEYBYTES, strlen($pk));
        $this->assertSame($sk . $pk, $keypair);

        // Test crypto_kx
        $alice_seed = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_KX_SEEDBYTES);
        $alice_keypair = ParagonIE_Sodium_Compat::crypto_kx_seed_keypair($alice_seed);
        $alice_sk = ParagonIE_Sodium_Compat::crypto_kx_secretkey($alice_keypair);
        $alice_pk = ParagonIE_Sodium_Compat::crypto_kx_publickey($alice_keypair);

        $bob_seed = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_KX_SEEDBYTES);
        $bob_keypair = ParagonIE_Sodium_Compat::crypto_kx_seed_keypair($bob_seed);
        $bob_sk = ParagonIE_Sodium_Compat::crypto_kx_secretkey($bob_keypair);
        $bob_pk = ParagonIE_Sodium_Compat::crypto_kx_publickey($bob_keypair);

        $server_pk = $bob_pk;
        $client_pk = $alice_pk;

        $tx = ParagonIE_Sodium_Compat::crypto_kx($alice_sk, $server_pk, $client_pk, $server_pk);
        $rx = ParagonIE_Sodium_Compat::crypto_kx($bob_sk, $client_pk, $client_pk, $server_pk);
        $this->assertSame($tx, $rx);
    }

    /**
     * @throws Exception
     */
    public function testKxInvalidInputs(): void
    {
        $key = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_KX_SECRETKEYBYTES);
        $pk = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_KX_PUBLICKEYBYTES);

        try {
            ParagonIE_Sodium_Compat::crypto_kx(substr($key, 1), $pk, $pk, $pk);
            $this->fail('Invalid my_secret length');
        } catch (SodiumException $ex) {
            $this->assertInstanceOf(SodiumException::class, $ex);
        }

        try {
            ParagonIE_Sodium_Compat::crypto_kx($key, substr($pk, 1), $pk, $pk);
            $this->fail('Invalid their_public length');
        } catch (SodiumException $ex) {
            $this->assertInstanceOf(SodiumException::class, $ex);
        }

        try {
            ParagonIE_Sodium_Compat::crypto_kx($key, $pk, substr($pk, 1), $pk);
            $this->fail('Invalid client_public length');
        } catch (SodiumException $ex) {
            $this->assertInstanceOf(SodiumException::class, $ex);
        }

        try {
            ParagonIE_Sodium_Compat::crypto_kx($key, $pk, $pk, substr($pk, 1));
            $this->fail('Invalid server_public length');
        } catch (SodiumException $ex) {
            $this->assertInstanceOf(SodiumException::class, $ex);
        }
    }

    /**
     * @throws SodiumException
     */
    public function testIsZero(): void
    {
        $this->assertTrue(ParagonIE_Sodium_Compat::is_zero(str_repeat("\0", 32)));
        $this->assertFalse(ParagonIE_Sodium_Compat::is_zero(random_bytes(32)));
    }

    /**
     * @throws SodiumException
     * @throws TypeError
     */
    public function testMemzero(): void
    {
        $this->expectException(SodiumException::class);
        $var = 'test';
        ParagonIE_Sodium_Compat::memzero($var);
    }

    /**
     * @throws Exception
     */
    public function testRandombytes(): void
    {
        $buf = ParagonIE_Sodium_Compat::randombytes_buf(16);
        $this->assertSame(16, strlen($buf));

        $uniform = ParagonIE_Sodium_Compat::randombytes_uniform(100);
        $this->assertIsInt($uniform);
        $this->assertGreaterThanOrEqual(0, $uniform);
        $this->assertLessThan(100, $uniform);

        $random16 = ParagonIE_Sodium_Compat::randombytes_random16();
        $this->assertIsInt($random16);
        $this->assertGreaterThanOrEqual(0, $random16);
        $this->assertLessThanOrEqual(65535, $random16);
    }

    public function testVersionFunctions(): void
    {
        $this->assertIsString(ParagonIE_Sodium_Compat::version_string());
        $this->assertIsInt(ParagonIE_Sodium_Compat::library_version_major());
        $this->assertIsInt(ParagonIE_Sodium_Compat::library_version_minor());
    }

    public function testGenericHash(): void
    {
        $expected = '22e1d241197a38fba37d57a7aa10d67b';
        $this->assertSame(
            $expected,
            ParagonIE_Sodium_Core_Util::bin2hex(
                ParagonIE_Sodium_Compat::crypto_generichash(
                    'Paragon Initiative Enterprises',
                    '',
                    16
                )
            )
        );
    }

    public function testGenericHashShortKey(): void
    {
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::crypto_generichash('', 'a');
    }

    public function testGenericHashLongKey(): void
    {
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::crypto_generichash('', str_repeat('a', 65));
    }

    public function testKDF(): void
    {
        $ikm = ParagonIE_Sodium_Compat::crypto_generichash('paragonie/sodium_compat');
        $expected = 'a9071767f30b4b38ed3624603a4fcb5f';
        $this->assertSame(
            $expected,
            ParagonIE_Sodium_Core_Util::bin2hex(
                ParagonIE_Sodium_Compat::crypto_kdf_derive_from_key(16, 1, 'testtest', $ikm)
            )
        );
    }

    public function testKDFShortIKM(): void
    {
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::crypto_kdf_derive_from_key(16, 1, 'testtest', 'a');
    }

    public function testKDFLongIKM(): void
    {
        $this->expectException(SodiumException::class);
        $long = str_repeat('a', 65);
        ParagonIE_Sodium_Compat::crypto_kdf_derive_from_key(16, 1, 'testtest', $long);
    }

    public function testKDFShortContext(): void
    {
        $ikm = ParagonIE_Sodium_Compat::crypto_generichash('paragonie/sodium_compat');
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::crypto_kdf_derive_from_key(16, 1, 'test', $ikm);
    }

    public function testKDFLongContext(): void
    {
        $ikm = ParagonIE_Sodium_Compat::crypto_generichash('paragonie/sodium_compat');
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::crypto_kdf_derive_from_key(16, 1, 'testtesttest', $ikm);
    }

    public function testKDFShortOutput(): void
    {
        $ikm = ParagonIE_Sodium_Compat::crypto_generichash('paragonie/sodium_compat');
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::crypto_kdf_derive_from_key(15, 1, 'testtest', $ikm);
    }

    public function testKDFLongOutput(): void
    {
        $ikm = ParagonIE_Sodium_Compat::crypto_generichash('paragonie/sodium_compat');
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::crypto_kdf_derive_from_key(65, 1, 'testtest', $ikm);
    }

    public function testKDFNegativeKeyID(): void
    {
        $ikm = ParagonIE_Sodium_Compat::crypto_generichash('paragonie/sodium_compat');
        $this->expectException(SodiumException::class);
        ParagonIE_Sodium_Compat::crypto_kdf_derive_from_key(32, -1, 'testtest', $ikm);
    }
}
