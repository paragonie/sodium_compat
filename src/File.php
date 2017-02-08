<?php

/**
 * Class ParagonIE_Sodium_File
 */
class ParagonIE_Sodium_File extends ParagonIE_Sodium_Core_Util
{
    const BUFFER_SIZE = 8192;

    /**
     * Sign a file (rather than a string). Uses less memory than
     * ParagonIE_Sodium_Compat::crypto_sign_detached(), but produces
     * the same result.
     *
     * @param string $filePath  Absolute path to a file on the filesystem
     * @param string $secretKey Secret signing key
     *
     * @return string           Ed25519 signature
     * @throws Error
     * @throws TypeError
     */
    public static function sign_file($filePath, $secretKey)
    {
        if (!is_string($filePath)) {
            throw new TypeError('Argument 1 must be a string.');
        }
        if (!is_string($secretKey)) {
            throw new TypeError('Argument 2 must be a string');
        }
        if (self::strlen($secretKey) !== ParagonIE_Sodium_Compat::CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new TypeError('Argument 2 must be CRYPTO_SIGN_SECRETKEYBYTES bytes');
        }

        /** @var resource $fp */
        $fp = fopen($filePath, 'rb');

        /** @var int $size */
        $size = filesize($filePath);
        if (!is_int($size) || !is_resource($fp)) {
            throw new Error('Could not open file for reading');
        }

        /** @var string $az */
        $az = hash('sha512', self::substr($secretKey, 0, 32), true);

        $az[0] = self::intToChr(self::chrToInt($az[0]) & 248);
        $az[31] = self::intToChr((self::chrToInt($az[31]) & 63) | 64);

        /** @var resource $hs */
        $hs = hash_init('sha512');
        hash_update($hs, self::substr($az, 32, 32));
        $hs = self::updateHashWithFile($hs, $fp, $size);

        /** @var string $nonceHash */
        $nonceHash = hash_final($hs, true);

        /** @var string $pk */
        $pk = self::substr($secretKey, 32, 32);

        /** @var string $nonce */
        $nonce = ParagonIE_Sodium_Core_Ed25519::sc_reduce($nonceHash) . self::substr($nonceHash, 32);

        /** @var string $sig */
        $sig = ParagonIE_Sodium_Core_Ed25519::ge_p3_tobytes(
            ParagonIE_Sodium_Core_Ed25519::ge_scalarmult_base($nonce)
        );

        /** @var resource $hs */
        $hs = hash_init('sha512');
        hash_update($hs, self::substr($sig, 0, 32));
        hash_update($hs, self::substr($pk, 0, 32));
        $hs = self::updateHashWithFile($hs, $fp, $size);

        /** @var string $hramHash */
        $hramHash = hash_final($hs, true);

        /** @var string $hram */
        $hram = ParagonIE_Sodium_Core_Ed25519::sc_reduce($hramHash);

        /** @var string $sigAfter */
        $sigAfter = ParagonIE_Sodium_Core_Ed25519::sc_muladd($hram, $az, $nonce);

        /** @var string $sig */
        $sig = self::substr($sig, 0, 32) . self::substr($sigAfter, 0, 32);

        try {
            ParagonIE_Sodium_Compat::memzero($az);
        } catch (Error $ex) {
            $az = null;
        }
        fclose($fp);
        return $sig;
    }

    /**
     * Verify a file (rather than a string). Uses less memory than
     * ParagonIE_Sodium_Compat::crypto_sign_verify_detached(), but
     * produces the same result.
     *
     * @param string $sig       Ed25519 signature
     * @param string $filePath  Absolute path to a file on the filesystem
     * @param string $publicKey Signing public key
     *
     * @return bool
     * @throws Error
     * @throws Exception
     */
    public static function verify_file($sig, $filePath, $publicKey)
    {
        if (!is_string($sig)) {
            throw new TypeError('Argument 1 must be a string.');
        }
        if (!is_string($filePath)) {
            throw new TypeError('Argument 2 must be a string.');
        }
        if (!is_string($publicKey)) {
            throw new TypeError('Argument 3 must be a string');
        }
        if (self::strlen($sig) !== ParagonIE_Sodium_Compat::CRYPTO_SIGN_BYTES) {
            throw new TypeError('Argument 1 must be CRYPTO_SIGN_BYTES bytes');
        }
        if (self::strlen($publicKey) !== ParagonIE_Sodium_Compat::CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new TypeError('Argument 3 must be CRYPTO_SIGN_PUBLICKEYBYTES bytes');
        }

        /** @var resource $fp */
        $fp = fopen($filePath, 'rb');

        /** @var int $size */
        $size = filesize($filePath);
        if (!is_int($size) || !is_resource($fp)) {
            throw new Error('Could not open file for reading');
        }
        if (self::strlen($sig) < 64) {
            throw new Exception('Signature is too short');
        }
        if (ParagonIE_Sodium_Core_Ed25519::check_S_lt_L(self::substr($sig, 32, 32))) {
            throw new Exception('S < L - Invalid signature');
        }
        if (ParagonIE_Sodium_Core_Ed25519::small_order($sig)) {
            throw new Exception('Signature is on too small of an order');
        }
        if ((self::chrToInt($sig[63]) & 224) !== 0) {
            throw new Exception('Invalid signature');
        }
        $d = 0;
        for ($i = 0; $i < 32; ++$i) {
            $d |= self::chrToInt($publicKey[$i]);
        }
        if ($d === 0) {
            throw new Exception('All zero public key');
        }

        /** @var bool The original value of ParagonIE_Sodium_Compat::$fastMult */
        $orig = ParagonIE_Sodium_Compat::$fastMult;

        // Set ParagonIE_Sodium_Compat::$fastMult to true to speed up verification.
        ParagonIE_Sodium_Compat::$fastMult = true;

        /** @var ParagonIE_Sodium_Core_Curve25519_Ge_P3 $A */
        $A = ParagonIE_Sodium_Core_Ed25519::ge_frombytes_negate_vartime($publicKey);

        /** @var resource $hs */
        $hs = hash_init('sha512');
        hash_update($hs, self::substr($sig, 0, 32));
        hash_update($hs, self::substr($publicKey, 0, 32));
        $hs = self::updateHashWithFile($hs, $fp, $size);
        /** @var string $hDigest */
        $hDigest = hash_final($hs, true);

        /** @var string $h */
        $h = ParagonIE_Sodium_Core_Ed25519::sc_reduce($hDigest) . self::substr($hDigest, 32);

        /** @var ParagonIE_Sodium_Core_Curve25519_Ge_P2 $R */
        $R = ParagonIE_Sodium_Core_Ed25519::ge_double_scalarmult_vartime(
            $h,
            $A,
            self::substr($sig, 32)
        );

        /** @var string $rcheck */
        $rcheck = ParagonIE_Sodium_Core_Ed25519::ge_tobytes($R);

        // Close the file handle
        fclose($fp);

        // Reset ParagonIE_Sodium_Compat::$fastMult to what it was before.
        ParagonIE_Sodium_Compat::$fastMult = $orig;
        return self::verify_32($rcheck, self::substr($sig, 0, 32));
    }

    /**
     * Update a hash context with the contents of a file, without
     * loading the entire file into memory.
     *
     * @param resource $hash
     * @param resource $fp
     * @param int $size
     * @return resource
     * @throws Error
     * @throws TypeError
     */
    public static function updateHashWithFile($hash, $fp, $size = 0)
    {
        if (!is_resource($hash)) {
            throw new TypeError('Argument 1 must be a resource');
        }
        if (!is_resource($fp)) {
            throw new TypeError('Argument 2 must be a resource');
        }
        if (!is_int($size)) {
            throw new TypeError('Argument 3 must be an integer');
        }
        /** @var int $originalPosition */
        $originalPosition = ftell($fp);

        // Move file pointer to beginning of file
        fseek($fp, 0, SEEK_SET);
        for ($i = 0; $i < $size; $i += self::BUFFER_SIZE) {
            /** @var string $message */
            $message = fread(
                $fp,
                ($size - $i) > self::BUFFER_SIZE
                    ? $size - $i
                    : self::BUFFER_SIZE
            );
            if (!is_string($message)) {
                throw new Error('Unexpected error reading from file.');
            }
            hash_update($hash, $message);
        }
        // Reset file pointer's position
        fseek($fp, $originalPosition, SEEK_SET);
        return $hash;
    }
}
