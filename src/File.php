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
        $fp = fopen($filePath, 'rb');
        $size = filesize($filePath);
        if ($size === false || !is_resource($fp)) {
            throw new Error('Could not open file for reading');
        }
        $az = hash('sha512', self::substr($secretKey, 0, 32), true);

        $az[0] = self::intToChr(self::chrToInt($az[0]) & 248);
        $az[31] = self::intToChr((self::chrToInt($az[31]) & 63) | 64);

        $hs = hash_init('sha512');
        hash_update($hs, self::substr($az, 32, 32));
        $hs = self::updateHashWithFile($hs, $fp, $size);
        $nonceHash = hash_final($hs, true);

        $pk = self::substr($secretKey, 32, 32);

        $nonce = ParagonIE_Sodium_Core_Ed25519::sc_reduce($nonceHash) . self::substr($nonceHash, 32);
        $sig = ParagonIE_Sodium_Core_Ed25519::ge_p3_tobytes(
            ParagonIE_Sodium_Core_Ed25519::ge_scalarmult_base($nonce)
        );

        $hs = hash_init('sha512');
        hash_update($hs, self::substr($sig, 0, 32));
        hash_update($hs, self::substr($pk, 0, 32));
        $hs = self::updateHashWithFile($hs, $fp, $size);
        $hramHash = hash_final($hs, true);

        $hram = ParagonIE_Sodium_Core_Ed25519::sc_reduce($hramHash);
        $sigAfter = ParagonIE_Sodium_Core_Ed25519::sc_muladd($hram, $az, $nonce);
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
        $fp = fopen($filePath, 'rb');
        $size = filesize($filePath);
        if ($size === false || !is_resource($fp)) {
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

        $A = ParagonIE_Sodium_Core_Ed25519::ge_frombytes_negate_vartime($publicKey);
        $d = 0;
        for ($i = 0; $i < 32; ++$i) {
            $d |= self::chrToInt($publicKey[$i]);
        }
        if ($d === 0) {
            throw new Exception('All zero public key');
        }

        $hs = hash_init('sha512');
        hash_update($hs, self::substr($sig, 0, 32));
        hash_update($hs, self::substr($publicKey, 0, 32));
        $hs = self::updateHashWithFile($hs, $fp, $size);
        $hDigest = hash_final($hs, true);

        $h = ParagonIE_Sodium_Core_Ed25519::sc_reduce($hDigest) . self::substr($hDigest, 32);
        $R = ParagonIE_Sodium_Core_Ed25519::ge_double_scalarmult_vartime(
            $h,
            $A,
            self::substr($sig, 32)
        );
        $rcheck = ParagonIE_Sodium_Core_Ed25519::ge_tobytes($R);
        fclose($fp);
        return self::verify_32($rcheck, self::substr($sig, 0, 32));
    }

    /**
     * @param resource $hash
     * @param resource $fp
     * @param int $size
     * @return resource
     */
    public static function updateHashWithFile($hash, $fp, $size = 0)
    {
        fseek($fp, 0, SEEK_SET);
        for ($i = 0; $i < $size; $i += self::BUFFER_SIZE) {
            $message = fread(
                $fp,
                ($size - $i) > self::BUFFER_SIZE
                    ? $size - $i
                    : self::BUFFER_SIZE
            );
            hash_update($hash, $message);
        }
        fseek($fp, 0, SEEK_SET);
        return $hash;
    }
}
