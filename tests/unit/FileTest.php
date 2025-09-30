<?php

use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(ParagonIE_Sodium_File::class)]
class FileTest extends TestCase
{
    private array $tempFiles = [];

    #[After]
    protected function tearDown(): void
    {
        foreach ($this->tempFiles as $file) {
            if (file_exists($file)) {
                unlink($file);
            }
        }
        $this->tempFiles = [];
    }

    private function createTempFile(string $content = ''): string
    {
        $filename = tempnam(sys_get_temp_dir(), 'sodium-compat-');
        if ($filename === false) {
            $this->fail('Failed to create temporary file.');
        }
        file_put_contents($filename, $content);
        $this->tempFiles[] = $filename;
        return $filename;
    }

    /**
     * @throws SodiumException
     * @throws TypeError
     * @throws Exception
     */
    public function testBox(): void
    {
        $content = 'test content for box';
        $inputFile = $this->createTempFile($content);
        $outputFile = $this->createTempFile();
        $decryptedFile = $this->createTempFile();

        $senderKeyPair = ParagonIE_Sodium_Compat::crypto_box_keypair();
        $recipientKeyPair = ParagonIE_Sodium_Compat::crypto_box_keypair();

        $nonce = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_BOX_NONCEBYTES);

        $senderBoxKey = ParagonIE_Sodium_Compat::crypto_box_keypair_from_secretkey_and_publickey(
            ParagonIE_Sodium_Compat::crypto_box_secretkey($senderKeyPair),
            ParagonIE_Sodium_Compat::crypto_box_publickey($recipientKeyPair)
        );

        $recipientBoxKey = ParagonIE_Sodium_Compat::crypto_box_keypair_from_secretkey_and_publickey(
            ParagonIE_Sodium_Compat::crypto_box_secretkey($recipientKeyPair),
            ParagonIE_Sodium_Compat::crypto_box_publickey($senderKeyPair)
        );

        ParagonIE_Sodium_File::box($inputFile, $outputFile, $nonce, $senderBoxKey);
        $this->assertNotSame($content, file_get_contents($outputFile));

        ParagonIE_Sodium_File::box_open($outputFile, $decryptedFile, $nonce, $recipientBoxKey);
        $this->assertSame($content, file_get_contents($decryptedFile));
    }

    /**
     * @throws Exception
     * @throws SodiumException
     * @throws TypeError
     */
    public function testGenericHash(): void
    {
        $content = 'test content';
        $file = $this->createTempFile($content);

        $hash = ParagonIE_Sodium_File::generichash($file);
        $this->assertSame(32, strlen($hash));

        $key = ParagonIE_Sodium_Compat::crypto_generichash_keygen();
        $hashWithKey = ParagonIE_Sodium_File::generichash($file, $key);
        $this->assertSame(32, strlen($hashWithKey));
        $this->assertNotSame($hash, $hashWithKey);
    }

    /**
     * @throws Exception
     * @throws SodiumException
     * @throws TypeError
     */
    public function testBoxSeal(): void
    {
        $content = 'test content for box_seal';
        $inputFile = $this->createTempFile($content);
        $outputFile = $this->createTempFile();
        $decryptedFile = $this->createTempFile();

        $keyPair = ParagonIE_Sodium_Compat::crypto_box_keypair();
        $publicKey = ParagonIE_Sodium_Compat::crypto_box_publickey($keyPair);

        ParagonIE_Sodium_File::box_seal($inputFile, $outputFile, $publicKey);
        $this->assertNotSame($content, file_get_contents($outputFile));

        ParagonIE_Sodium_File::box_seal_open($outputFile, $decryptedFile, $keyPair);
        $this->assertSame($content, file_get_contents($decryptedFile));
    }

    /**
     * @throws SodiumException
     */
    public function testSecretBox(): void
    {
        $content = 'test content for secretbox';
        $inputFile = $this->createTempFile($content);
        $outputFile = $this->createTempFile();
        $decryptedFile = $this->createTempFile();

        $key = ParagonIE_Sodium_Compat::crypto_secretbox_keygen();
        $nonce = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_SECRETBOX_NONCEBYTES);

        ParagonIE_Sodium_File::secretbox($inputFile, $outputFile, $nonce, $key);
        $this->assertNotSame($content, file_get_contents($outputFile));

        ParagonIE_Sodium_File::secretbox_open($outputFile, $decryptedFile, $nonce, $key);
        $this->assertSame($content, file_get_contents($decryptedFile));
    }

    public function testSign(): void
    {
        $content = 'test content for sign';
        $file = $this->createTempFile($content);

        $keyPair = ParagonIE_Sodium_Compat::crypto_sign_keypair();
        $secretKey = ParagonIE_Sodium_Compat::crypto_sign_secretkey($keyPair);
        $publicKey = ParagonIE_Sodium_Compat::crypto_sign_publickey($keyPair);

        $signature = ParagonIE_Sodium_File::sign($file, $secretKey);
        $this->assertSame(ParagonIE_Sodium_Compat::CRYPTO_SIGN_BYTES, strlen($signature));

        $this->assertTrue(ParagonIE_Sodium_File::verify($signature, $file, $publicKey));
    }

    /**
     * @return void
     * @throws SodiumException
     */
    public function testBoxInvalidNonce(): void
    {
        $inputFile = $this->createTempFile('test');
        $outputFile = $this->createTempFile();
        $keyPair = ParagonIE_Sodium_Compat::crypto_box_keypair();

        $this->expectException(TypeError::class);
        ParagonIE_Sodium_File::box(
            $inputFile,
            $outputFile,
            'invalid-nonce',
            $keyPair
        );
    }

    /**
     * @throws Exception
     * @throws SodiumException
     */
    public function testBoxInvalidKeyPair(): void
    {
        $inputFile = $this->createTempFile('test');
        $outputFile = $this->createTempFile();
        $nonce = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_BOX_NONCEBYTES);

        $this->expectException(TypeError::class);
        ParagonIE_Sodium_File::box(
            $inputFile,
            $outputFile,
            $nonce,
            'invalid-keypair'
        );
    }

    /**
     * @throws Exception
     * @throws SodiumException
     */
    public function testBoxUnreadableInput(): void
    {
        $outputFile = $this->createTempFile();
        $nonce = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_BOX_NONCEBYTES);
        $keyPair = ParagonIE_Sodium_Compat::crypto_box_keypair();

        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Could not obtain the file size');
        ParagonIE_Sodium_File::box(
            '/tmp/unexisting-file-we-hope',
            $outputFile,
            $nonce,
            $keyPair
        );
    }

    /**
     * @throws Exception
     * @throws SodiumException
     */
    public function testSecretboxOpenWithInvalidKey(): void
    {
        $content = 'test content for secretbox';
        $inputFile = $this->createTempFile($content);
        $outputFile = $this->createTempFile();
        $decryptedFile = $this->createTempFile();

        $key = ParagonIE_Sodium_Compat::crypto_secretbox_keygen();
        $invalidKey = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_SECRETBOX_KEYBYTES);
        $nonce = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_SECRETBOX_NONCEBYTES);

        ParagonIE_Sodium_File::secretbox($inputFile, $outputFile, $nonce, $key);

        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Invalid MAC');
        ParagonIE_Sodium_File::secretbox_open($outputFile, $decryptedFile, $nonce, $invalidKey);
    }

    /**
     * @throws Exception
     * @throws SodiumException
     */
    public function testBoxSealInvalidPublicKey(): void
    {
        $inputFile = $this->createTempFile('test');
        $outputFile = $this->createTempFile();

        $this->expectException(TypeError::class);
        ParagonIE_Sodium_File::box_seal(
            $inputFile,
            $outputFile,
            'invalid-public-key'
        );
    }

    /**
     * @throws Exception
     * @throws SodiumException
     */
    public function testSignInvalidSecretKey(): void
    {
        $file = $this->createTempFile('test content for sign');

        $this->expectException(TypeError::class);
        ParagonIE_Sodium_File::sign($file, 'invalid-secret-key');
    }

    /**
     * @throws Exception
     * @throws SodiumException
     */
    public function testBoxUnwritableOutput(): void
    {
        $inputFile = $this->createTempFile('test');
        $outputFile = tempnam(sys_get_temp_dir(), 'sodium-compat-');
        if ($outputFile === false) {
            $this->fail('Failed to create temporary file.');
        }
        $this->tempFiles[] = $outputFile;
        $nonce = random_bytes(ParagonIE_Sodium_Compat::CRYPTO_BOX_NONCEBYTES);
        $keyPair = ParagonIE_Sodium_Compat::crypto_box_keypair();

        chmod($outputFile, 0444);

        try {
            $this->expectException(SodiumException::class);
            $this->expectExceptionMessage('Could not open output file for writing');
            ParagonIE_Sodium_File::box(
                $inputFile,
                $outputFile,
                $nonce,
                $keyPair
            );
        } finally {
            chmod($outputFile, 0644);
        }
    }

    /**
     * @throws SodiumException
     */
    public function testBoxSealOpenTruncated(): void
    {
        $inputFile = $this->createTempFile('short');
        $outputFile = $this->createTempFile();
        $keyPair = ParagonIE_Sodium_Compat::crypto_box_keypair();

        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('Could not read public key from sealed file');
        ParagonIE_Sodium_File::box_seal_open(
            $inputFile,
            $outputFile,
            $keyPair
        );
    }

    /**
     * @return void
     * @throws SodiumException
     */
    public function testVerifyAllZeroPublicKey(): void
    {
        $file = $this->createTempFile('test');

        // Create a valid signature first
        $keyPair = ParagonIE_Sodium_Compat::crypto_sign_keypair();
        $secretKey = ParagonIE_Sodium_Compat::crypto_sign_secretkey($keyPair);
        $signature = ParagonIE_Sodium_File::sign($file, $secretKey);

        // Now use an all-zero public key
        $publicKey = str_repeat("\0", ParagonIE_Sodium_Compat::CRYPTO_SIGN_PUBLICKEYBYTES);

        $this->expectException(SodiumException::class);
        $this->expectExceptionMessage('All zero public key');
        ParagonIE_Sodium_File::verify($signature, $file, $publicKey);
    }

    /**
     * @throws SodiumException
     */
    public function testUpdateHashWithFile(): void
    {
        $file = 'test.txt';
        $data = 'abcdefghij';
        file_put_contents($file, $data);

        $fp = fopen($file, 'rb');
        $hash = hash_init('sha256');
        ParagonIE_Sodium_File::updateHashWithFile($hash, $fp, 10);
        $fromFunc = hash_final($hash);
        fclose($fp);

        $read = file_get_contents($file);
        $fromFile = hash('sha256', substr($read, 0, 10));

        $this->assertSame($fromFile, $fromFunc);
        unlink($file);
    }
}
