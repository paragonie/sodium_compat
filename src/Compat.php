<?php
declare(strict_types=1);

/**
 * Libsodium compatibility layer
 *
 * This is the only class you should be interfacing with, as a user of
 * sodium_compat.
 *
 * If the PHP extension for libsodium is installed, it will always use that
 * instead of our implementations. You get better performance and stronger
 * guarantees against side-channels that way.
 *
 * However, if your users don't have the PHP extension installed, we offer a
 * compatible interface here. It will give you the correct results as if the
 * PHP extension was installed. It won't be as fast, of course.
 *
 * CAUTION * CAUTION * CAUTION * CAUTION * CAUTION * CAUTION * CAUTION * CAUTION *
 *                                                                               *
 *     Until audited, this is probably not safe to use! DANGER WILL ROBINSON     *
 *                                                                               *
 * CAUTION * CAUTION * CAUTION * CAUTION * CAUTION * CAUTION * CAUTION * CAUTION *
 */

if (class_exists('ParagonIE_Sodium_Compat', false)) {
    return;
}

class ParagonIE_Sodium_Compat
{
    /**
     * This parameter prevents the use of the PECL extension.
     * It should only be used for unit testing.
     *
     * @var bool
     */
    public static bool $disableFallbackForUnitTests = false;

    /**
     * Use fast multiplication rather than our constant-time multiplication
     * implementation. Can be enabled at runtime. Only enable this if you
     * are absolutely certain that there is no timing leak on your platform.
     *
     * @var bool
     */
    public static bool $fastMult = false;

    const LIBRARY_MAJOR_VERSION = 9;
    const LIBRARY_MINOR_VERSION = 1;
    const LIBRARY_VERSION_MAJOR = 9;
    const LIBRARY_VERSION_MINOR = 1;
    const VERSION_STRING = 'polyfill-1.0.8';

    // From libsodium
    const BASE64_VARIANT_ORIGINAL = 1;
    const BASE64_VARIANT_ORIGINAL_NO_PADDING = 3;
    const BASE64_VARIANT_URLSAFE = 5;
    const BASE64_VARIANT_URLSAFE_NO_PADDING = 7;
    const CRYPTO_AEAD_AES256GCM_KEYBYTES = 32;
    const CRYPTO_AEAD_AES256GCM_NSECBYTES = 0;
    const CRYPTO_AEAD_AES256GCM_NPUBBYTES = 12;
    const CRYPTO_AEAD_AES256GCM_ABYTES = 16;
    const CRYPTO_AEAD_AEGIS128L_KEYBYTES = 16;
    const CRYPTO_AEAD_AEGIS128L_NSECBYTES = 0;
    const CRYPTO_AEAD_AEGIS128L_NPUBBYTES = 16;
    const CRYPTO_AEAD_AEGIS128L_ABYTES = 32;
    const CRYPTO_AEAD_AEGIS256_KEYBYTES = 32;
    const CRYPTO_AEAD_AEGIS256_NSECBYTES = 0;
    const CRYPTO_AEAD_AEGIS256_NPUBBYTES = 32;
    const CRYPTO_AEAD_AEGIS256_ABYTES = 32;
    const CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES = 32;
    const CRYPTO_AEAD_CHACHA20POLY1305_NSECBYTES = 0;
    const CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES = 8;
    const CRYPTO_AEAD_CHACHA20POLY1305_ABYTES = 16;
    const CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES = 32;
    const CRYPTO_AEAD_CHACHA20POLY1305_IETF_NSECBYTES = 0;
    const CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES = 12;
    const CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES = 16;
    const CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES = 32;
    const CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NSECBYTES = 0;
    const CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES = 24;
    const CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES = 16;
    const CRYPTO_AUTH_BYTES = 32;
    const CRYPTO_AUTH_KEYBYTES = 32;
    const CRYPTO_BOX_SEALBYTES = 16;
    const CRYPTO_BOX_SECRETKEYBYTES = 32;
    const CRYPTO_BOX_PUBLICKEYBYTES = 32;
    const CRYPTO_BOX_KEYPAIRBYTES = 64;
    const CRYPTO_BOX_MACBYTES = 16;
    const CRYPTO_BOX_NONCEBYTES = 24;
    const CRYPTO_BOX_SEEDBYTES = 32;
    const CRYPTO_CORE_RISTRETTO255_BYTES = 32;
    const CRYPTO_CORE_RISTRETTO255_SCALARBYTES = 32;
    const CRYPTO_CORE_RISTRETTO255_HASHBYTES = 64;
    const CRYPTO_CORE_RISTRETTO255_NONREDUCEDSCALARBYTES = 64;
    const CRYPTO_KDF_BYTES_MIN = 16;
    const CRYPTO_KDF_BYTES_MAX = 64;
    const CRYPTO_KDF_CONTEXTBYTES = 8;
    const CRYPTO_KDF_KEYBYTES = 32;
    const CRYPTO_KX_BYTES = 32;
    const CRYPTO_KX_PRIMITIVE = 'x25519blake2b';
    const CRYPTO_KX_SEEDBYTES = 32;
    const CRYPTO_KX_KEYPAIRBYTES = 64;
    const CRYPTO_KX_PUBLICKEYBYTES = 32;
    const CRYPTO_KX_SECRETKEYBYTES = 32;
    const CRYPTO_KX_SESSIONKEYBYTES = 32;
    const CRYPTO_GENERICHASH_BYTES = 32;
    const CRYPTO_GENERICHASH_BYTES_MIN = 16;
    const CRYPTO_GENERICHASH_BYTES_MAX = 64;
    const CRYPTO_GENERICHASH_KEYBYTES = 32;
    const CRYPTO_GENERICHASH_KEYBYTES_MIN = 16;
    const CRYPTO_GENERICHASH_KEYBYTES_MAX = 64;
    const CRYPTO_PWHASH_SALTBYTES = 16;
    const CRYPTO_PWHASH_STRPREFIX = '$argon2id$';
    const CRYPTO_PWHASH_ALG_ARGON2I13 = 1;
    const CRYPTO_PWHASH_ALG_ARGON2ID13 = 2;
    const CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE = 33554432;
    const CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE = 4;
    const CRYPTO_PWHASH_MEMLIMIT_MODERATE = 134217728;
    const CRYPTO_PWHASH_OPSLIMIT_MODERATE = 6;
    const CRYPTO_PWHASH_MEMLIMIT_SENSITIVE = 536870912;
    const CRYPTO_PWHASH_OPSLIMIT_SENSITIVE = 8;
    const CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES = 32;
    const CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRPREFIX = '$7$';
    const CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE = 534288;
    const CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE = 16777216;
    const CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_SENSITIVE = 33554432;
    const CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_SENSITIVE = 1073741824;
    const CRYPTO_SCALARMULT_BYTES = 32;
    const CRYPTO_SCALARMULT_SCALARBYTES = 32;
    const CRYPTO_SCALARMULT_RISTRETTO255_BYTES = 32;
    const CRYPTO_SCALARMULT_RISTRETTO255_SCALARBYTES = 32;
    const CRYPTO_SHORTHASH_BYTES = 8;
    const CRYPTO_SHORTHASH_KEYBYTES = 16;
    const CRYPTO_SECRETBOX_KEYBYTES = 32;
    const CRYPTO_SECRETBOX_MACBYTES = 16;
    const CRYPTO_SECRETBOX_NONCEBYTES = 24;
    const CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES = 17;
    const CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES = 24;
    const CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES = 32;
    const CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PUSH = 0;
    const CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_PULL = 1;
    const CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_REKEY = 2;
    const CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL = 3;
    const CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_MESSAGEBYTES_MAX = 0x3fffffff80;
    const CRYPTO_SIGN_BYTES = 64;
    const CRYPTO_SIGN_SEEDBYTES = 32;
    const CRYPTO_SIGN_PUBLICKEYBYTES = 32;
    const CRYPTO_SIGN_SECRETKEYBYTES = 64;
    const CRYPTO_SIGN_KEYPAIRBYTES = 96;
    const CRYPTO_STREAM_KEYBYTES = 32;
    const CRYPTO_STREAM_NONCEBYTES = 24;
    const CRYPTO_STREAM_XCHACHA20_KEYBYTES = 32;
    const CRYPTO_STREAM_XCHACHA20_NONCEBYTES = 24;

    /**
     * Add two numbers (little-endian unsigned), storing the value in the first
     * parameter.
     *
     * This mutates $val.
     *
     * @param string $val
     * @param string $addv
     * @return void
     * @throws SodiumException
     */
    public static function add(
        #[SensitiveParameter]
        string &$val,
        #[SensitiveParameter]
        string $addv
    ): void {
        $val_len = ParagonIE_Sodium_Core_Util::strlen($val);
        $addv_len = ParagonIE_Sodium_Core_Util::strlen($addv);
        if ($val_len !== $addv_len) {
            throw new SodiumException('values must have the same length');
        }
        $A = ParagonIE_Sodium_Core_Util::stringToIntArray($val);
        $B = ParagonIE_Sodium_Core_Util::stringToIntArray($addv);

        $c = 0;
        for ($i = 0; $i < $val_len; $i++) {
            $c += ($A[$i] + $B[$i]);
            $A[$i] = ($c & 0xff);
            $c >>= 8;
        }
        $val = ParagonIE_Sodium_Core_Util::intArrayToString($A);
    }

    /**
     * @param string $encoded
     * @param int $variant
     * @param string $ignore
     * @return string
     * @throws SodiumException
     */
    public static function base642bin(
        #[SensitiveParameter]
        string $encoded,
        int $variant,
        string $ignore = ''
    ): string {
        if (ParagonIE_Sodium_Core_Util::strlen($encoded) === 0) {
            return '';
        }

        // Just strip before decoding
        if (!empty($ignore)) {
            $encoded = str_replace($ignore, '', $encoded);
        }

        try {
            return match ($variant) {
                self::BASE64_VARIANT_ORIGINAL => ParagonIE_Sodium_Core_Base64_Original::decode($encoded, true),
                self::BASE64_VARIANT_ORIGINAL_NO_PADDING => ParagonIE_Sodium_Core_Base64_Original::decode($encoded),
                self::BASE64_VARIANT_URLSAFE => ParagonIE_Sodium_Core_Base64_UrlSafe::decode($encoded, true),
                self::BASE64_VARIANT_URLSAFE_NO_PADDING => ParagonIE_Sodium_Core_Base64_UrlSafe::decode($encoded),
                default => throw new SodiumException('invalid base64 variant identifier'),
            };
        } catch (Exception $ex) {
            if ($ex instanceof SodiumException) {
                throw $ex;
            }
            throw new SodiumException('invalid base64 string');
        }
    }

    /**
     * @param string $decoded
     * @param int $variant
     * @return string
     * @throws SodiumException
     */
    public static function bin2base64(
        #[SensitiveParameter]
        string $decoded,
        int $variant
    ): string {
        if (ParagonIE_Sodium_Core_Util::strlen($decoded) === 0) {
            return '';
        }

        return match ($variant) {
            self::BASE64_VARIANT_ORIGINAL => ParagonIE_Sodium_Core_Base64_Original::encode($decoded),
            self::BASE64_VARIANT_ORIGINAL_NO_PADDING => ParagonIE_Sodium_Core_Base64_Original::encodeUnpadded($decoded),
            self::BASE64_VARIANT_URLSAFE => ParagonIE_Sodium_Core_Base64_UrlSafe::encode($decoded),
            self::BASE64_VARIANT_URLSAFE_NO_PADDING => ParagonIE_Sodium_Core_Base64_UrlSafe::encodeUnpadded($decoded),
            default => throw new SodiumException('invalid base64 variant identifier'),
        };
    }

    /**
     * Cache-timing-safe implementation of bin2hex().
     *
     * @param string $string A string (probably raw binary)
     * @return string        A hexadecimal-encoded string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function bin2hex(
        #[SensitiveParameter]
        string $string
    ): string {
        if (self::useNewSodiumAPI()) {
            return sodium_bin2hex($string);
        }
        if (self::use_fallback('bin2hex')) {
            return (string) call_user_func('\\Sodium\\bin2hex', $string);
        }
        return ParagonIE_Sodium_Core_Util::bin2hex($string);
    }

    /**
     * Compare two strings, in constant-time.
     * Compared to memcmp(), compare() is more useful for sorting.
     *
     * @param string $left  The left operand; must be a string
     * @param string $right The right operand; must be a string
     * @return int          If < 0 if the left operand is less than the right
     *                      If = 0 if both strings are equal
     *                      If > 0 if the right operand is less than the left
     * @throws SodiumException
     * @throws TypeError
     */
    public static function compare(
        #[SensitiveParameter]
        string $left,
        #[SensitiveParameter]
        string $right
    ): int {
        if (self::useNewSodiumAPI()) {
            return sodium_compare($left, $right);
        }
        if (self::use_fallback('compare')) {
            return (int) call_user_func('\\Sodium\\compare', $left, $right);
        }
        return ParagonIE_Sodium_Core_Util::compare($left, $right);
    }

    /**
     * Authenticated Encryption with Associated Data: Decryption
     *
     * Algorithm:
     *     AEGIS-128L
     *
     * @param string $ciphertext Encrypted message (with MAC appended)
     * @param string $assocData  Authenticated Associated Data (unencrypted)
     * @param string $nonce      Number to be used only Once; must be 32 bytes
     * @param string $key        Encryption key
     *
     * @return string            The original plaintext message
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_aead_aegis128l_decrypt(
        string $ciphertext = '',
        string $assocData = '',
        string $nonce = '',
        #[SensitiveParameter]
        string $key = ''
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_AEAD_AEGIS128L_NPUBBYTES) {
            throw new SodiumException('Nonce must be CRYPTO_AEAD_AEGIS_128L_NPUBBYTES long');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_AEAD_AEGIS128L_KEYBYTES) {
            throw new SodiumException('Key must be CRYPTO_AEAD_AEGIS128L_KEYBYTES long');
        }
        $ct_length = ParagonIE_Sodium_Core_Util::strlen($ciphertext);
        if ($ct_length < self::CRYPTO_AEAD_AEGIS128L_ABYTES) {
            throw new SodiumException('Message must be at least CRYPTO_AEAD_AEGIS128L_ABYTES long');
        }

        $ct = ParagonIE_Sodium_Core_Util::substr(
            $ciphertext,
            0,
            $ct_length - self::CRYPTO_AEAD_AEGIS128L_ABYTES
        );
        $tag = ParagonIE_Sodium_Core_Util::substr(
            $ciphertext,
            $ct_length - self::CRYPTO_AEAD_AEGIS128L_ABYTES,
            self::CRYPTO_AEAD_AEGIS128L_ABYTES
        );
        return ParagonIE_Sodium_Core_AEGIS128L::decrypt($ct, $tag, $assocData, $key, $nonce);
    }

    /**
     * Authenticated Encryption with Associated Data: Encryption
     *
     * Algorithm:
     *     AEGIS-128L
     *
     * @param string $plaintext Message to be encrypted
     * @param string $assocData Authenticated Associated Data (unencrypted)
     * @param string $nonce     Number to be used only Once; must be 32 bytes
     * @param string $key       Encryption key
     *
     * @return string           Ciphertext with 32-byte authentication tag appended
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_aead_aegis128l_encrypt(
        #[SensitiveParameter]
        string $plaintext = '',
        string $assocData = '',
        string $nonce = '',
        #[SensitiveParameter]
        string $key = ''
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_AEAD_AEGIS128L_NPUBBYTES) {
            throw new SodiumException('Nonce must be CRYPTO_AEAD_AEGIS128L_KEYBYTES long');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_AEAD_AEGIS128L_KEYBYTES) {
            throw new SodiumException('Key must be CRYPTO_AEAD_AEGIS128L_KEYBYTES long');
        }

        list($ct, $tag) = ParagonIE_Sodium_Core_AEGIS128L::encrypt($plaintext, $assocData, $key, $nonce);
        return $ct . $tag;
    }

    /**
     * Return a secure random key for use with the AEGIS-128L
     * symmetric AEAD interface.
     *
     * @return string
     * @throws Exception
     * @throws Error
     */
    public static function crypto_aead_aegis128l_keygen(): string
    {
        return random_bytes(self::CRYPTO_AEAD_AEGIS128L_KEYBYTES);
    }

    /**
     * Authenticated Encryption with Associated Data: Decryption
     *
     * Algorithm:
     *     AEGIS-256
     *
     * @param string $ciphertext Encrypted message (with MAC appended)
     * @param string $assocData  Authenticated Associated Data (unencrypted)
     * @param string $nonce      Number to be used only Once; must be 32 bytes
     * @param string $key        Encryption key
     *
     * @return string|bool       The original plaintext message
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_aead_aegis256_decrypt(
        string $ciphertext = '',
        string $assocData = '',
        string $nonce = '',
        #[SensitiveParameter]
        string $key = ''
    ): string|bool {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_AEAD_AEGIS256_NPUBBYTES) {
            throw new SodiumException('Nonce must be CRYPTO_AEAD_AEGIS256_NPUBBYTES long');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_AEAD_AEGIS256_KEYBYTES) {
            throw new SodiumException('Key must be CRYPTO_AEAD_AEGIS256_KEYBYTES long');
        }
        $ct_length = ParagonIE_Sodium_Core_Util::strlen($ciphertext);
        if ($ct_length < self::CRYPTO_AEAD_AEGIS256_ABYTES) {
            throw new SodiumException('Message must be at least CRYPTO_AEAD_AEGIS256_ABYTES long');
        }

        $ct = ParagonIE_Sodium_Core_Util::substr(
            $ciphertext,
            0,
            $ct_length - self::CRYPTO_AEAD_AEGIS256_ABYTES
        );
        $tag = ParagonIE_Sodium_Core_Util::substr(
            $ciphertext,
            $ct_length - self::CRYPTO_AEAD_AEGIS256_ABYTES,
            self::CRYPTO_AEAD_AEGIS256_ABYTES
        );
        return ParagonIE_Sodium_Core_AEGIS256::decrypt($ct, $tag, $assocData, $key, $nonce);
    }

    /**
     * Authenticated Encryption with Associated Data: Encryption
     *
     * Algorithm:
     *     AEGIS-256
     *
     * @param string $plaintext Message to be encrypted
     * @param string $assocData Authenticated Associated Data (unencrypted)
     * @param string $nonce Number to be used only Once; must be 32 bytes
     * @param string $key Encryption key
     *
     * @return string           Ciphertext with 32-byte authentication tag appended
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_aead_aegis256_encrypt(
        #[SensitiveParameter]
        string $plaintext = '',
        string $assocData = '',
        string $nonce = '',
        #[SensitiveParameter]
        string $key = ''
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_AEAD_AEGIS256_NPUBBYTES) {
            throw new SodiumException('Nonce must be CRYPTO_AEAD_AEGIS128L_KEYBYTES long');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_AEAD_AEGIS256_KEYBYTES) {
            throw new SodiumException('Key must be CRYPTO_AEAD_AEGIS128L_KEYBYTES long');
        }

        list($ct, $tag) = ParagonIE_Sodium_Core_AEGIS256::encrypt($plaintext, $assocData, $key, $nonce);
        return $ct . $tag;
    }

    /**
     * Return a secure random key for use with the AEGIS-256
     * symmetric AEAD interface.
     *
     * @return string
     * @throws Exception
     * @throws Error
     */
    public static function crypto_aead_aegis256_keygen(): string
    {
        return random_bytes(self::CRYPTO_AEAD_AEGIS256_KEYBYTES);
    }

    /**
     * Is AES-256-GCM even available to use?
     *
     * @return bool
     */
    public static function crypto_aead_aes256gcm_is_available(): bool
    {
        if (self::useNewSodiumAPI()) {
            return sodium_crypto_aead_aes256gcm_is_available();
        }
        if (self::use_fallback('crypto_aead_aes256gcm_is_available')) {
            return call_user_func('\\Sodium\\crypto_aead_aes256gcm_is_available');
        }
        if (!is_callable('openssl_encrypt') || !is_callable('openssl_decrypt')) {
            // OpenSSL isn't installed
            return false;
        }
        return in_array('aes-256-gcm', openssl_get_cipher_methods());
    }

    /**
     * Authenticated Encryption with Associated Data: Decryption
     *
     * Algorithm:
     *     AES-256-GCM
     *
     * This mode uses a 64-bit random nonce with a 64-bit counter.
     * IETF mode uses a 96-bit random nonce with a 32-bit counter.
     *
     * @param string $ciphertext Encrypted message (with Poly1305 MAC appended)
     * @param string $assocData  Authenticated Associated Data (unencrypted)
     * @param string $nonce      Number to be used only Once; must be 8 bytes
     * @param string $key        Encryption key
     *
     * @return string|bool       The original plaintext message
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_aead_aes256gcm_decrypt(
        string $ciphertext = '',
        string $assocData = '',
        string $nonce = '',
        #[SensitiveParameter]
        string $key = ''
    ): string|bool {
        if (!self::crypto_aead_aes256gcm_is_available()) {
            throw new SodiumException('AES-256-GCM is not available');
        }
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_AEAD_AES256GCM_NPUBBYTES) {
            throw new SodiumException('Nonce must be CRYPTO_AEAD_AES256GCM_NPUBBYTES long');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_AEAD_AES256GCM_KEYBYTES) {
            throw new SodiumException('Key must be CRYPTO_AEAD_AES256GCM_KEYBYTES long');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($ciphertext) < self::CRYPTO_AEAD_AES256GCM_ABYTES) {
            throw new SodiumException('Message must be at least CRYPTO_AEAD_AES256GCM_ABYTES long');
        }
        if (!is_callable('openssl_decrypt')) {
            throw new SodiumException('The OpenSSL extension is not installed, or openssl_decrypt() is not available');
        }

        $ctext = ParagonIE_Sodium_Core_Util::substr($ciphertext, 0, -self::CRYPTO_AEAD_AES256GCM_ABYTES);
        $authTag = ParagonIE_Sodium_Core_Util::substr($ciphertext, -self::CRYPTO_AEAD_AES256GCM_ABYTES, 16);
        return openssl_decrypt(
            $ctext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $authTag,
            $assocData
        );
    }

    /**
     * Authenticated Encryption with Associated Data: Encryption
     *
     * Algorithm:
     *     AES-256-GCM
     *
     * @param string $plaintext Message to be encrypted
     * @param string $assocData Authenticated Associated Data (unencrypted)
     * @param string $nonce     Number to be used only Once; must be 8 bytes
     * @param string $key       Encryption key
     *
     * @return string           Ciphertext with a 16-byte GCM message
     *                          authentication code appended
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_aead_aes256gcm_encrypt(
        #[SensitiveParameter]
        string $plaintext = '',
        string $assocData = '',
        string $nonce = '',
        #[SensitiveParameter]
        string $key = ''
    ): string {
        if (!self::crypto_aead_aes256gcm_is_available()) {
            throw new SodiumException('AES-256-GCM is not available');
        }

        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_AEAD_AES256GCM_NPUBBYTES) {
            throw new SodiumException('Nonce must be CRYPTO_AEAD_AES256GCM_NPUBBYTES long');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_AEAD_AES256GCM_KEYBYTES) {
            throw new SodiumException('Key must be CRYPTO_AEAD_AES256GCM_KEYBYTES long');
        }

        if (!is_callable('openssl_encrypt')) {
            throw new SodiumException('The OpenSSL extension is not installed, or openssl_encrypt() is not available');
        }

        $authTag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $authTag,
            $assocData
        );
        return $ciphertext . $authTag;
    }

    /**
     * Return a secure random key for use with the AES-256-GCM
     * symmetric AEAD interface.
     *
     * @return string
     * @throws Exception
     * @throws Error
     */
    public static function crypto_aead_aes256gcm_keygen(): string
    {
        return random_bytes(self::CRYPTO_AEAD_AES256GCM_KEYBYTES);
    }

    /**
     * Authenticated Encryption with Associated Data: Decryption
     *
     * Algorithm:
     *     ChaCha20-Poly1305
     *
     * This mode uses a 64-bit random nonce with a 64-bit counter.
     * IETF mode uses a 96-bit random nonce with a 32-bit counter.
     *
     * @param string $ciphertext Encrypted message (with Poly1305 MAC appended)
     * @param string $assocData  Authenticated Associated Data (unencrypted)
     * @param string $nonce      Number to be used only Once; must be 8 bytes
     * @param string $key        Encryption key
     *
     * @return string|bool       The original plaintext message
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_aead_chacha20poly1305_decrypt(
        string $ciphertext = '',
        string $assocData = '',
        string $nonce = '',
        #[SensitiveParameter]
        string $key = ''
    ): string|bool {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES) {
            throw new SodiumException('Nonce must be CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES long');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES) {
            throw new SodiumException('Key must be CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES long');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($ciphertext) < self::CRYPTO_AEAD_CHACHA20POLY1305_ABYTES) {
            throw new SodiumException('Message must be at least CRYPTO_AEAD_CHACHA20POLY1305_ABYTES long');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_aead_chacha20poly1305_decrypt(
                $ciphertext,
                $assocData,
                $nonce,
                $key
            );
        }
        if (self::use_fallback('crypto_aead_chacha20poly1305_decrypt')) {
            return call_user_func(
                '\\Sodium\\crypto_aead_chacha20poly1305_decrypt',
                $ciphertext,
                $assocData,
                $nonce,
                $key
            );
        }
        return ParagonIE_Sodium_Crypto::aead_chacha20poly1305_decrypt(
            $ciphertext,
            $assocData,
            $nonce,
            $key
        );
    }

    /**
     * Authenticated Encryption with Associated Data
     *
     * Algorithm:
     *     ChaCha20-Poly1305
     *
     * This mode uses a 64-bit random nonce with a 64-bit counter.
     * IETF mode uses a 96-bit random nonce with a 32-bit counter.
     *
     * @param string $plaintext Message to be encrypted
     * @param string $assocData Authenticated Associated Data (unencrypted)
     * @param string $nonce     Number to be used only Once; must be 8 bytes
     * @param string $key       Encryption key
     *
     * @return string           Ciphertext with a 16-byte Poly1305 message
     *                          authentication code appended
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_aead_chacha20poly1305_encrypt(
        #[SensitiveParameter]
        string $plaintext = '',
        string $assocData = '',
        string $nonce = '',
        #[SensitiveParameter]
        string $key = ''
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES) {
            throw new SodiumException('Nonce must be CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES long');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES) {
            throw new SodiumException('Key must be CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES long');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_aead_chacha20poly1305_encrypt(
                $plaintext,
                $assocData,
                $nonce,
                $key
            );
        }
        if (self::use_fallback('crypto_aead_chacha20poly1305_encrypt')) {
            return (string) call_user_func(
                '\\Sodium\\crypto_aead_chacha20poly1305_encrypt',
                $plaintext,
                $assocData,
                $nonce,
                $key
            );
        }
        return ParagonIE_Sodium_Crypto::aead_chacha20poly1305_encrypt(
            $plaintext,
            $assocData,
            $nonce,
            $key
        );
    }

    /**
     * Authenticated Encryption with Associated Data: Decryption
     *
     * Algorithm:
     *     ChaCha20-Poly1305
     *
     * IETF mode uses a 96-bit random nonce with a 32-bit counter.
     * Regular mode uses a 64-bit random nonce with a 64-bit counter.
     *
     * @param string $ciphertext Encrypted message (with Poly1305 MAC appended)
     * @param string $assocData  Authenticated Associated Data (unencrypted)
     * @param string $nonce      Number to be used only Once; must be 12 bytes
     * @param string $key        Encryption key
     *
     * @return string|bool      The original plaintext message
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_aead_chacha20poly1305_ietf_decrypt(
        string $ciphertext = '',
        string $assocData = '',
        string $nonce = '',
        #[SensitiveParameter]
        string $key = ''
    ): string|bool {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES) {
            throw new SodiumException('Nonce must be CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES long');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES) {
            throw new SodiumException('Key must be CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES long');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($ciphertext) < self::CRYPTO_AEAD_CHACHA20POLY1305_ABYTES) {
            throw new SodiumException('Message must be at least CRYPTO_AEAD_CHACHA20POLY1305_ABYTES long');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_aead_chacha20poly1305_ietf_decrypt(
                $ciphertext,
                $assocData,
                $nonce,
                $key
            );
        }
        if (self::use_fallback('crypto_aead_chacha20poly1305_ietf_decrypt')) {
            return call_user_func(
                '\\Sodium\\crypto_aead_chacha20poly1305_ietf_decrypt',
                $ciphertext,
                $assocData,
                $nonce,
                $key
            );
        }
        return ParagonIE_Sodium_Crypto::aead_chacha20poly1305_ietf_decrypt(
            $ciphertext,
            $assocData,
            $nonce,
            $key
        );
    }

    /**
     * Return a secure random key for use with the ChaCha20-Poly1305
     * symmetric AEAD interface.
     *
     * @return string
     * @throws Exception
     * @throws Error
     */
    public static function crypto_aead_chacha20poly1305_keygen(): string
    {
        return random_bytes(self::CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES);
    }

    /**
     * Authenticated Encryption with Associated Data
     *
     * Algorithm:
     *     ChaCha20-Poly1305
     *
     * IETF mode uses a 96-bit random nonce with a 32-bit counter.
     * Regular mode uses a 64-bit random nonce with a 64-bit counter.
     *
     * @param string $plaintext Message to be encrypted
     * @param string $assocData Authenticated Associated Data (unencrypted)
     * @param string $nonce Number to be used only Once; must be 8 bytes
     * @param string $key Encryption key
     *
     * @return string           Ciphertext with a 16-byte Poly1305 message
     *                          authentication code appended
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_aead_chacha20poly1305_ietf_encrypt(
        #[SensitiveParameter]
        string $plaintext = '',
        string $assocData = '',
        string $nonce = '',
        #[SensitiveParameter]
        string $key = ''
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES) {
            throw new SodiumException('Nonce must be CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES long');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES) {
            throw new SodiumException('Key must be CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES long');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_aead_chacha20poly1305_ietf_encrypt(
                $plaintext,
                $assocData,
                $nonce,
                $key
            );
        }
        if (self::use_fallback('crypto_aead_chacha20poly1305_ietf_encrypt')) {
            return (string) call_user_func(
                '\\Sodium\\crypto_aead_chacha20poly1305_ietf_encrypt',
                $plaintext,
                $assocData,
                $nonce,
                $key
            );
        }
        return ParagonIE_Sodium_Crypto::aead_chacha20poly1305_ietf_encrypt(
            $plaintext,
            $assocData,
            $nonce,
            $key
        );
    }

    /**
     * Return a secure random key for use with the ChaCha20-Poly1305
     * symmetric AEAD interface. (IETF version)
     *
     * @return string
     * @throws Exception
     * @throws Error
     */
    public static function crypto_aead_chacha20poly1305_ietf_keygen(): string
    {
        return random_bytes(self::CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES);
    }

    /**
     * Authenticated Encryption with Associated Data: Decryption
     *
     * Algorithm:
     *     XChaCha20-Poly1305
     *
     * This mode uses a 64-bit random nonce with a 64-bit counter.
     * IETF mode uses a 96-bit random nonce with a 32-bit counter.
     *
     * @param string $ciphertext   Encrypted message (with Poly1305 MAC appended)
     * @param string $assocData    Authenticated Associated Data (unencrypted)
     * @param string $nonce        Number to be used only Once; must be 8 bytes
     * @param string $key          Encryption key
     * @param bool   $dontFallback Don't fallback to ext/sodium
     *
     * @return string|bool         The original plaintext message
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_aead_xchacha20poly1305_ietf_decrypt(
        string $ciphertext = '',
        string $assocData = '',
        string $nonce = '',
        #[SensitiveParameter]
        string $key = '',
        bool $dontFallback = false
    ): string|bool {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES) {
            throw new SodiumException('Nonce must be CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES long');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES) {
            throw new SodiumException('Key must be CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES long');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($ciphertext) < self::CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES) {
            throw new SodiumException('Message must be at least CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES long');
        }
        if (self::useNewSodiumAPI() && !$dontFallback) {
            if (is_callable('sodium_crypto_aead_xchacha20poly1305_ietf_decrypt')) {
                return sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                    $ciphertext,
                    $assocData,
                    $nonce,
                    $key
                );
            }
        }

        return ParagonIE_Sodium_Crypto::aead_xchacha20poly1305_ietf_decrypt(
            $ciphertext,
            $assocData,
            $nonce,
            $key
        );
    }

    /**
     * Authenticated Encryption with Associated Data
     *
     * Algorithm:
     *     XChaCha20-Poly1305
     *
     * This mode uses a 64-bit random nonce with a 64-bit counter.
     * IETF mode uses a 96-bit random nonce with a 32-bit counter.
     *
     * @param string $plaintext    Message to be encrypted
     * @param string $assocData    Authenticated Associated Data (unencrypted)
     * @param string $nonce        Number to be used only Once; must be 8 bytes
     * @param string $key          Encryption key
     * @param bool   $dontFallback Don't fallback to ext/sodium
     *
     * @return string           Ciphertext with a 16-byte Poly1305 message
     *                          authentication code appended
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_aead_xchacha20poly1305_ietf_encrypt(
        #[SensitiveParameter]
        string $plaintext = '',
        string $assocData = '',
        string $nonce = '',
        #[SensitiveParameter]
        string $key = '',
        bool $dontFallback = false
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES) {
            throw new SodiumException('Nonce must be CRYPTO_AEAD_XCHACHA20POLY1305_NPUBBYTES long');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES) {
            throw new SodiumException('Key must be CRYPTO_AEAD_XCHACHA20POLY1305_KEYBYTES long');
        }
        if (self::useNewSodiumAPI() && !$dontFallback) {
            if (is_callable('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt')) {
                return sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                    $plaintext,
                    $assocData,
                    $nonce,
                    $key
                );
            }
        }

        return ParagonIE_Sodium_Crypto::aead_xchacha20poly1305_ietf_encrypt(
            $plaintext,
            $assocData,
            $nonce,
            $key
        );
    }

    /**
     * Return a secure random key for use with the XChaCha20-Poly1305
     * symmetric AEAD interface.
     *
     * @return string
     * @throws Exception
     * @throws Error
     */
    public static function crypto_aead_xchacha20poly1305_ietf_keygen(): string
    {
        return random_bytes(self::CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);
    }

    /**
     * Authenticate a message. Uses symmetric-key cryptography.
     *
     * Algorithm:
     *     HMAC-SHA512-256. Which is HMAC-SHA-512 truncated to 256 bits.
     *     Not to be confused with HMAC-SHA-512/256 which would use the
     *     SHA-512/256 hash function (uses different initial parameters
     *     but still truncates to 256 bits to sidestep length-extension
     *     attacks).
     *
     * @param string $message Message to be authenticated
     * @param string $key Symmetric authentication key
     * @return string         Message authentication code
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_auth(
        string $message,
        #[SensitiveParameter]
        string $key
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_AUTH_KEYBYTES) {
            throw new SodiumException('Argument 2 must be CRYPTO_AUTH_KEYBYTES long.');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_auth($message, $key);
        }
        if (self::use_fallback('crypto_auth')) {
            return (string) call_user_func('\\Sodium\\crypto_auth', $message, $key);
        }
        return ParagonIE_Sodium_Crypto::auth($message, $key);
    }

    /**
     * @return string
     * @throws Exception
     * @throws Error
     */
    public static function crypto_auth_keygen(): string
    {
        return random_bytes(self::CRYPTO_AUTH_KEYBYTES);
    }

    /**
     * Verify the MAC of a message previously authenticated with crypto_auth.
     *
     * @param string $mac Message authentication code
     * @param string $message Message whose authenticity you are attempting to
     *                        verify (with a given MAC and key)
     * @param string $key Symmetric authentication key
     * @return bool           TRUE if authenticated, FALSE otherwise
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_auth_verify(
        string $mac,
        string $message,
        #[SensitiveParameter]
        string $key
    ): bool {

        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($mac) !== self::CRYPTO_AUTH_BYTES) {
            throw new SodiumException('Argument 1 must be CRYPTO_AUTH_BYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_AUTH_KEYBYTES) {
            throw new SodiumException('Argument 3 must be CRYPTO_AUTH_KEYBYTES long.');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_auth_verify($mac, $message, $key);
        }
        if (self::use_fallback('crypto_auth_verify')) {
            return (bool) call_user_func('\\Sodium\\crypto_auth_verify', $mac, $message, $key);
        }
        return ParagonIE_Sodium_Crypto::auth_verify($mac, $message, $key);
    }

    /**
     * Authenticated asymmetric-key encryption. Both the sender and recipient
     * may decrypt messages.
     *
     * Algorithm: X25519-XSalsa20-Poly1305.
     *     X25519: Elliptic-Curve Diffie Hellman over Curve25519.
     *     XSalsa20: Extended-nonce variant of salsa20.
     *     Poyl1305: Polynomial MAC for one-time message authentication.
     *
     * @param string $plaintext The message to be encrypted
     * @param string $nonce A Number to only be used Once; must be 24 bytes
     * @param string $keypair Your secret key and your recipient's public key
     * @return string           Ciphertext with 16-byte Poly1305 MAC
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_box(
        #[SensitiveParameter]
        string $plaintext,
        string $nonce,
        #[SensitiveParameter]
        string $keypair
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_BOX_NONCEBYTES) {
            throw new SodiumException('Argument 2 must be CRYPTO_BOX_NONCEBYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($keypair) !== self::CRYPTO_BOX_KEYPAIRBYTES) {
            throw new SodiumException('Argument 3 must be CRYPTO_BOX_KEYPAIRBYTES long.');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_box($plaintext, $nonce, $keypair);
        }
        if (self::use_fallback('crypto_box')) {
            return (string) call_user_func('\\Sodium\\crypto_box', $plaintext, $nonce, $keypair);
        }
        return ParagonIE_Sodium_Crypto::box($plaintext, $nonce, $keypair);
    }

    /**
     * Anonymous public-key encryption. Only the recipient may decrypt messages.
     *
     * Algorithm: X25519-XSalsa20-Poly1305, as with crypto_box.
     *     The sender's X25519 keypair is ephemeral.
     *     Nonce is generated from the BLAKE2b hash of both public keys.
     *
     * This provides ciphertext integrity.
     *
     * @param string $plaintext Message to be sealed
     * @param string $publicKey Your recipient's public key
     * @return string           Sealed message that only your recipient can
     *                          decrypt
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_box_seal(
        #[SensitiveParameter]
        string $plaintext,
        string $publicKey
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($publicKey) !== self::CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new SodiumException('Argument 2 must be CRYPTO_BOX_PUBLICKEYBYTES long.');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_box_seal($plaintext, $publicKey);
        }
        if (self::use_fallback('crypto_box_seal')) {
            return (string) call_user_func('\\Sodium\\crypto_box_seal', $plaintext, $publicKey);
        }
        return ParagonIE_Sodium_Crypto::box_seal($plaintext, $publicKey);
    }

    /**
     * Opens a message encrypted with crypto_box_seal(). Requires
     * the recipient's keypair (sk || pk) to decrypt successfully.
     *
     * This validates ciphertext integrity.
     *
     * @param string $ciphertext Sealed message to be opened
     * @param string $keypair    Your crypto_box keypair
     * @return string|bool       The original plaintext message
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_box_seal_open(
        string $ciphertext,
        string $keypair
    ): string|bool {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($keypair) !== self::CRYPTO_BOX_KEYPAIRBYTES) {
            throw new SodiumException('Argument 2 must be CRYPTO_BOX_KEYPAIRBYTES long.');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_box_seal_open($ciphertext, $keypair);
        }
        if (self::use_fallback('crypto_box_seal_open')) {
            return call_user_func('\\Sodium\\crypto_box_seal_open', $ciphertext, $keypair);
        }
        return ParagonIE_Sodium_Crypto::box_seal_open($ciphertext, $keypair);
    }

    /**
     * Generate a new random X25519 keypair.
     *
     * @return string A 64-byte string; the first 32 are your secret key, while
     *                the last 32 are your public key. crypto_box_secretkey()
     *                and crypto_box_publickey() exist to separate them so you
     *                don't accidentally get them mixed up!
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_box_keypair(): string
    {
        if (self::useNewSodiumAPI()) {
            return sodium_crypto_box_keypair();
        }
        if (self::use_fallback('crypto_box_keypair')) {
            return (string) call_user_func('\\Sodium\\crypto_box_keypair');
        }
        return ParagonIE_Sodium_Crypto::box_keypair();
    }

    /**
     * Combine two keys into a keypair for use in library methods that expect
     * a keypair. This doesn't necessarily have to be the same person's keys.
     *
     * @param string $secretKey Secret key
     * @param string $publicKey Public key
     * @return string    Keypair
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_box_keypair_from_secretkey_and_publickey(
        #[SensitiveParameter]
        string $secretKey,
        string $publicKey
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($secretKey) !== self::CRYPTO_BOX_SECRETKEYBYTES) {
            throw new SodiumException('Argument 1 must be CRYPTO_BOX_SECRETKEYBYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($publicKey) !== self::CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new SodiumException('Argument 2 must be CRYPTO_BOX_PUBLICKEYBYTES long.');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_box_keypair_from_secretkey_and_publickey($secretKey, $publicKey);
        }
        if (self::use_fallback('crypto_box_keypair_from_secretkey_and_publickey')) {
            return (string) call_user_func('\\Sodium\\crypto_box_keypair_from_secretkey_and_publickey', $secretKey, $publicKey);
        }
        return ParagonIE_Sodium_Crypto::box_keypair_from_secretkey_and_publickey($secretKey, $publicKey);
    }

    /**
     * Decrypt a message previously encrypted with crypto_box().
     *
     * @param string $ciphertext Encrypted message
     * @param string $nonce      Number to only be used Once; must be 24 bytes
     * @param string $keypair    Your secret key and the sender's public key
     * @return string|bool       The original plaintext message
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_box_open(
        string $ciphertext,
        string $nonce,
        #[SensitiveParameter]
        string $keypair
    ): string|bool {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($ciphertext) < self::CRYPTO_BOX_MACBYTES) {
            throw new SodiumException('Argument 1 must be at least CRYPTO_BOX_MACBYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_BOX_NONCEBYTES) {
            throw new SodiumException('Argument 2 must be CRYPTO_BOX_NONCEBYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($keypair) !== self::CRYPTO_BOX_KEYPAIRBYTES) {
            throw new SodiumException('Argument 3 must be CRYPTO_BOX_KEYPAIRBYTES long.');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_box_open($ciphertext, $nonce, $keypair);
        }
        if (self::use_fallback('crypto_box_open')) {
            return call_user_func('\\Sodium\\crypto_box_open', $ciphertext, $nonce, $keypair);
        }
        return ParagonIE_Sodium_Crypto::box_open($ciphertext, $nonce, $keypair);
    }

    /**
     * Extract the public key from a crypto_box keypair.
     *
     * @param string $keypair Keypair containing secret and public key
     * @return string         Your crypto_box public key
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_box_publickey(
        #[SensitiveParameter]
        string $keypair
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($keypair) !== self::CRYPTO_BOX_KEYPAIRBYTES) {
            throw new SodiumException('Argument 1 must be CRYPTO_BOX_KEYPAIRBYTES long.');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_box_publickey($keypair);
        }
        if (self::use_fallback('crypto_box_publickey')) {
            return (string) call_user_func('\\Sodium\\crypto_box_publickey', $keypair);
        }
        return ParagonIE_Sodium_Crypto::box_publickey($keypair);
    }

    /**
     * Calculate the X25519 public key from a given X25519 secret key.
     *
     * @param string $secretKey Any X25519 secret key
     * @return string           The corresponding X25519 public key
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_box_publickey_from_secretkey(
        string $secretKey
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($secretKey) !== self::CRYPTO_BOX_SECRETKEYBYTES) {
            throw new SodiumException('Argument 1 must be CRYPTO_BOX_SECRETKEYBYTES long.');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_box_publickey_from_secretkey($secretKey);
        }
        if (self::use_fallback('crypto_box_publickey_from_secretkey')) {
            return (string) call_user_func('\\Sodium\\crypto_box_publickey_from_secretkey', $secretKey);
        }
        return ParagonIE_Sodium_Crypto::box_publickey_from_secretkey($secretKey);
    }

    /**
     * Extract the secret key from a crypto_box keypair.
     *
     * @param string $keypair
     * @return string         Your crypto_box secret key
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_box_secretkey(
        #[SensitiveParameter]
        string $keypair
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($keypair) !== self::CRYPTO_BOX_KEYPAIRBYTES) {
            throw new SodiumException('Argument 1 must be CRYPTO_BOX_KEYPAIRBYTES long.');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_box_secretkey($keypair);
        }
        if (self::use_fallback('crypto_box_secretkey')) {
            return (string) call_user_func('\\Sodium\\crypto_box_secretkey', $keypair);
        }
        return ParagonIE_Sodium_Crypto::box_secretkey($keypair);
    }

    /**
     * Generate an X25519 keypair from a seed.
     *
     * @param string $seed
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_box_seed_keypair(
        #[SensitiveParameter]
        string $seed
    ): string {
        if (self::useNewSodiumAPI()) {
            return sodium_crypto_box_seed_keypair($seed);
        }
        if (self::use_fallback('crypto_box_seed_keypair')) {
            return (string) call_user_func('\\Sodium\\crypto_box_seed_keypair', $seed);
        }
        return ParagonIE_Sodium_Crypto::box_seed_keypair($seed);
    }

    /**
     * Calculates a BLAKE2b hash, with an optional key.
     *
     * @param string      $message The message to be hashed
     * @param string|null $key     If specified, must be a string between 16
     *                             and 64 bytes long
     * @param int         $length  Output length in bytes; must be between 16
     *                             and 64 (default = 32)
     * @return string              Raw binary
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_generichash(
        string $message,
        #[SensitiveParameter]
        ?string $key = '',
        int $length = self::CRYPTO_GENERICHASH_BYTES
    ): string {
        if (is_null($key)) {
            $key = '';
        }
        /* Input validation: */
        if (!empty($key)) {
            if (ParagonIE_Sodium_Core_Util::strlen($key) < self::CRYPTO_GENERICHASH_KEYBYTES_MIN) {
                throw new SodiumException('Unsupported key size. Must be at least CRYPTO_GENERICHASH_KEYBYTES_MIN bytes long.');
            }
            if (ParagonIE_Sodium_Core_Util::strlen($key) > self::CRYPTO_GENERICHASH_KEYBYTES_MAX) {
                throw new SodiumException('Unsupported key size. Must be at most CRYPTO_GENERICHASH_KEYBYTES_MAX bytes long.');
            }
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_generichash($message, $key, $length);
        }
        if (self::use_fallback('crypto_generichash')) {
            return (string) call_user_func('\\Sodium\\crypto_generichash', $message, $key, $length);
        }
        return ParagonIE_Sodium_Crypto::generichash($message, $key, $length);
    }

    /**
     * Get the final BLAKE2b hash output for a given context.
     *
     * @param string $ctx BLAKE2 hashing context. Generated by crypto_generichash_init().
     * @param int $length Hash output size.
     * @return string     Final BLAKE2b hash.
     * @throws SodiumException
     * @throws TypeError
     * @psalm-suppress ReferenceConstraintViolation
     */
    public static function crypto_generichash_final(
        string &$ctx,
        int $length = self::CRYPTO_GENERICHASH_BYTES
    ): string {
        if (self::useNewSodiumAPI()) {
            return sodium_crypto_generichash_final($ctx, $length);
        }
        if (self::use_fallback('crypto_generichash_final')) {
            $func = '\\Sodium\\crypto_generichash_final';
            return (string) $func($ctx, $length);
        }
        if ($length < 1) {
            try {
                self::memzero($ctx);
            } catch (SodiumException) {
                unset($ctx);
            }
            return '';
        }
        $result = ParagonIE_Sodium_Crypto::generichash_final($ctx, $length);
        try {
            self::memzero($ctx);
        } catch (SodiumException) {
            unset($ctx);
        }
        return $result;
    }

    /**
     * Initialize a BLAKE2b hashing context, for use in a streaming interface.
     *
     * @param string|null $key If specified must be a string between 16 and 64 bytes
     * @param int $length      The size of the desired hash output
     * @return string          A BLAKE2 hashing context, encoded as a string
     *                         (To be 100% compatible with ext/libsodium)
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_generichash_init(
        #[SensitiveParameter]
        ?string $key = '',
        int $length = self::CRYPTO_GENERICHASH_BYTES
    ): string {
        if (is_null($key)) {
            $key = '';
        }

        /* Input validation: */
        if (!empty($key)) {
            if (ParagonIE_Sodium_Core_Util::strlen($key) < self::CRYPTO_GENERICHASH_KEYBYTES_MIN) {
                throw new SodiumException('Unsupported key size. Must be at least CRYPTO_GENERICHASH_KEYBYTES_MIN bytes long.');
            }
            if (ParagonIE_Sodium_Core_Util::strlen($key) > self::CRYPTO_GENERICHASH_KEYBYTES_MAX) {
                throw new SodiumException('Unsupported key size. Must be at most CRYPTO_GENERICHASH_KEYBYTES_MAX bytes long.');
            }
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_generichash_init($key, $length);
        }
        if (self::use_fallback('crypto_generichash_init')) {
            return (string) call_user_func('\\Sodium\\crypto_generichash_init', $key, $length);
        }
        return ParagonIE_Sodium_Crypto::generichash_init($key, $length);
    }

    /**
     * Initialize a BLAKE2b hashing context, for use in a streaming interface.
     *
     * @param string|null $key If specified must be a string between 16 and 64 bytes
     * @param int $length      The size of the desired hash output
     * @param string $salt     Salt (up to 16 bytes)
     * @param string $personal Personalization string (up to 16 bytes)
     * @return string          A BLAKE2 hashing context, encoded as a string
     *                         (To be 100% compatible with ext/libsodium)
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_generichash_init_salt_personal(
        #[SensitiveParameter]
        ?string $key = '',
        int $length = self::CRYPTO_GENERICHASH_BYTES,
        string $salt = '',
        string $personal = ''
    ): string {
        if (is_null($key)) {
            $key = '';
        }
        $salt = str_pad($salt, 16, "\0");
        $personal = str_pad($personal, 16, "\0");

        /* Input validation: */
        if (!empty($key)) {
            if (ParagonIE_Sodium_Core_Util::strlen($key) > self::CRYPTO_GENERICHASH_KEYBYTES_MAX) {
                throw new SodiumException('Unsupported key size. Must be at most CRYPTO_GENERICHASH_KEYBYTES_MAX bytes long.');
            }
        }
        return ParagonIE_Sodium_Crypto::generichash_init_salt_personal($key, $length, $salt, $personal);
    }

    /**
     * Update a BLAKE2b hashing context with additional data.
     *
     * @param string $ctx    BLAKE2 hashing context. Generated by crypto_generichash_init().
     *                       $ctx is passed by reference and gets updated in-place.
     * @param-out string $ctx
     * @param string $message The message to append to the existing hash state.
     * @return void
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_generichash_update(string &$ctx, string $message): void
    {
        if (self::useNewSodiumAPI()) {
            sodium_crypto_generichash_update($ctx, $message);
            return;
        }
        if (self::use_fallback('crypto_generichash_update')) {
            $func = '\\Sodium\\crypto_generichash_update';
            $func($ctx, $message);
            return;
        }
        $ctx = ParagonIE_Sodium_Crypto::generichash_update($ctx, $message);
    }

    /**
     * @return string
     * @throws Exception
     * @throws Error
     */
    public static function crypto_generichash_keygen(): string
    {
        return random_bytes(self::CRYPTO_GENERICHASH_KEYBYTES);
    }

    /**
     * @param int $subkey_len
     * @param int $subkey_id
     * @param string $context
     * @param string $key
     * @return string
     * @throws SodiumException
     */
    public static function crypto_kdf_derive_from_key(
        int $subkey_len,
        int $subkey_id,
        string $context,
        #[SensitiveParameter]
        string $key
    ): string {
        if ($subkey_len < self::CRYPTO_KDF_BYTES_MIN) {
            throw new SodiumException('subkey cannot be smaller than SODIUM_CRYPTO_KDF_BYTES_MIN');
        }
        if ($subkey_len > self::CRYPTO_KDF_BYTES_MAX) {
            throw new SodiumException('subkey cannot be larger than SODIUM_CRYPTO_KDF_BYTES_MAX');
        }
        if ($subkey_id < 0) {
            throw new SodiumException('subkey_id cannot be negative');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($context) !== self::CRYPTO_KDF_CONTEXTBYTES) {
            throw new SodiumException('context should be SODIUM_CRYPTO_KDF_CONTEXTBYTES bytes');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_KDF_KEYBYTES) {
            throw new SodiumException('key should be SODIUM_CRYPTO_KDF_KEYBYTES bytes');
        }

        $salt = ParagonIE_Sodium_Core_Util::store64_le($subkey_id);
        $state = self::crypto_generichash_init_salt_personal(
            $key,
            $subkey_len,
            $salt,
            $context
        );
        return self::crypto_generichash_final($state, $subkey_len);
    }

    /**
     * @return string
     * @throws Exception
     * @throws Error
     */
    public static function crypto_kdf_keygen(): string
    {
        return random_bytes(self::CRYPTO_KDF_KEYBYTES);
    }

    /**
     * Perform a key exchange, between a designated client and a server.
     *
     * Typically, you would designate one machine to be the client and the
     * other to be the server. The first two keys are what you'd expect for
     * scalarmult() below, but the latter two public keys don't swap places.
     *
     * | ALICE                          | BOB                                 |
     * | Client                         | Server                              |
     * |--------------------------------|-------------------------------------|
     * | shared = crypto_kx(            | shared = crypto_kx(                 |
     * |     alice_sk,                  |     bob_sk,                         | <- contextual
     * |     bob_pk,                    |     alice_pk,                       | <- contextual
     * |     alice_pk,                  |     alice_pk,                       | <----- static
     * |     bob_pk                     |     bob_pk                          | <----- static
     * | )                              | )                                   |
     *
     * They are used along with the scalarmult product to generate a 256-bit
     * BLAKE2b hash unique to the client and server keys.
     *
     * @param string $my_secret
     * @param string $their_public
     * @param string $client_public
     * @param string $server_public
     * @param bool $dontFallback
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_kx(
        #[SensitiveParameter]
        string $my_secret,
        string $their_public,
        string $client_public,
        string $server_public,
        bool $dontFallback = false
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($my_secret) !== self::CRYPTO_BOX_SECRETKEYBYTES) {
            throw new SodiumException('Argument 1 must be CRYPTO_BOX_SECRETKEYBYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($their_public) !== self::CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new SodiumException('Argument 2 must be CRYPTO_BOX_PUBLICKEYBYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($client_public) !== self::CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new SodiumException('Argument 3 must be CRYPTO_BOX_PUBLICKEYBYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($server_public) !== self::CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new SodiumException('Argument 4 must be CRYPTO_BOX_PUBLICKEYBYTES long.');
        }

        if (self::useNewSodiumAPI() && !$dontFallback) {
            if (is_callable('sodium_crypto_kx')) {
                return sodium_crypto_kx(
                    $my_secret,
                    $their_public,
                    $client_public,
                    $server_public
                );
            }
        }
        if (self::use_fallback('crypto_kx')) {
            return call_user_func(
                '\\Sodium\\crypto_kx',
                $my_secret,
                $their_public,
                $client_public,
                $server_public
            );
        }
        return ParagonIE_Sodium_Crypto::keyExchange(
            $my_secret,
            $their_public,
            $client_public,
            $server_public
        );
    }

    /**
     * @param string $seed
     * @return string
     * @throws SodiumException
     */
    public static function crypto_kx_seed_keypair(
        #[SensitiveParameter]
        string $seed
    ): string {
        if (ParagonIE_Sodium_Core_Util::strlen($seed) !== self::CRYPTO_KX_SEEDBYTES) {
            throw new SodiumException('seed must be SODIUM_CRYPTO_KX_SEEDBYTES bytes');
        }

        $sk = self::crypto_generichash($seed, '', self::CRYPTO_KX_SECRETKEYBYTES);
        $pk = self::crypto_scalarmult_base($sk);
        return $sk . $pk;
    }

    /**
     * @return string
     * @throws Exception
     */
    public static function crypto_kx_keypair(): string
    {
        $sk = self::randombytes_buf(self::CRYPTO_KX_SECRETKEYBYTES);
        $pk = self::crypto_scalarmult_base($sk);
        return $sk . $pk;
    }

    /**
     * @param string $keypair
     * @param string $serverPublicKey
     * @return array{0: string, 1: string}
     * @throws SodiumException
     */
    public static function crypto_kx_client_session_keys(
        #[SensitiveParameter]
        string $keypair,
        string $serverPublicKey
    ): array {
        if (ParagonIE_Sodium_Core_Util::strlen($keypair) !== self::CRYPTO_KX_KEYPAIRBYTES) {
            throw new SodiumException('keypair should be SODIUM_CRYPTO_KX_KEYPAIRBYTES bytes');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($serverPublicKey) !== self::CRYPTO_KX_PUBLICKEYBYTES) {
            throw new SodiumException('public keys must be SODIUM_CRYPTO_KX_PUBLICKEYBYTES bytes');
        }

        $sk = self::crypto_kx_secretkey($keypair);
        $pk = self::crypto_kx_publickey($keypair);
        $h = self::crypto_generichash_init(null, self::CRYPTO_KX_SESSIONKEYBYTES * 2);
        self::crypto_generichash_update($h, self::crypto_scalarmult($sk, $serverPublicKey));
        self::crypto_generichash_update($h, $pk);
        self::crypto_generichash_update($h, $serverPublicKey);
        $sessionKeys = self::crypto_generichash_final($h, self::CRYPTO_KX_SESSIONKEYBYTES * 2);
        return array(
            ParagonIE_Sodium_Core_Util::substr(
                $sessionKeys,
                0,
                self::CRYPTO_KX_SESSIONKEYBYTES
            ),
            ParagonIE_Sodium_Core_Util::substr(
                $sessionKeys,
                self::CRYPTO_KX_SESSIONKEYBYTES,
                self::CRYPTO_KX_SESSIONKEYBYTES
            )
        );
    }

    /**
     * @param string $keypair
     * @param string $clientPublicKey
     * @return array{0: string, 1: string}
     * @throws SodiumException
     */
    public static function crypto_kx_server_session_keys(
        #[SensitiveParameter]
        string $keypair,
        string $clientPublicKey
    ): array {
        if (ParagonIE_Sodium_Core_Util::strlen($keypair) !== self::CRYPTO_KX_KEYPAIRBYTES) {
            throw new SodiumException('keypair should be SODIUM_CRYPTO_KX_KEYPAIRBYTES bytes');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($clientPublicKey) !== self::CRYPTO_KX_PUBLICKEYBYTES) {
            throw new SodiumException('public keys must be SODIUM_CRYPTO_KX_PUBLICKEYBYTES bytes');
        }

        $sk = self::crypto_kx_secretkey($keypair);
        $pk = self::crypto_kx_publickey($keypair);
        $h = self::crypto_generichash_init(null, self::CRYPTO_KX_SESSIONKEYBYTES * 2);
        self::crypto_generichash_update($h, self::crypto_scalarmult($sk, $clientPublicKey));
        self::crypto_generichash_update($h, $clientPublicKey);
        self::crypto_generichash_update($h, $pk);
        $sessionKeys = self::crypto_generichash_final($h, self::CRYPTO_KX_SESSIONKEYBYTES * 2);
        return array(
            ParagonIE_Sodium_Core_Util::substr(
                $sessionKeys,
                self::CRYPTO_KX_SESSIONKEYBYTES,
                self::CRYPTO_KX_SESSIONKEYBYTES
            ),
            ParagonIE_Sodium_Core_Util::substr(
                $sessionKeys,
                0,
                self::CRYPTO_KX_SESSIONKEYBYTES
            )
        );
    }

    /**
     * @param string $kp
     * @return string
     * @throws SodiumException
     */
    public static function crypto_kx_secretkey(
        #[SensitiveParameter]
        string $kp
    ): string {
        return ParagonIE_Sodium_Core_Util::substr(
            $kp,
            0,
            self::CRYPTO_KX_SECRETKEYBYTES
        );
    }

    /**
     * @param string $kp
     * @return string
     * @throws SodiumException
     */
    public static function crypto_kx_publickey(
        string $kp
    ): string {
        return ParagonIE_Sodium_Core_Util::substr(
            $kp,
            self::CRYPTO_KX_SECRETKEYBYTES,
            self::CRYPTO_KX_PUBLICKEYBYTES
        );
    }

    /**
     * @param int $outlen
     * @param string $passwd
     * @param string $salt
     * @param int $opslimit
     * @param int $memlimit
     * @param int|null $alg
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_pwhash(
        int $outlen,
        #[SensitiveParameter]
        string $passwd,
        #[SensitiveParameter]
        string $salt,
        int $opslimit,
        int $memlimit,
        int $alg = null
    ): string {
        if (self::useNewSodiumAPI()) {
            if (!is_null($alg)) {
                return sodium_crypto_pwhash($outlen, $passwd, $salt, $opslimit, $memlimit, $alg);
            }
            return sodium_crypto_pwhash($outlen, $passwd, $salt, $opslimit, $memlimit);
        }
        if (self::use_fallback('crypto_pwhash')) {
            return (string) call_user_func('\\Sodium\\crypto_pwhash', $outlen, $passwd, $salt, $opslimit, $memlimit);
        }
        // This is the best we can do.
        throw new SodiumException(
            'This is not implemented, as it is not possible to implement Argon2i with acceptable performance in pure-PHP'
        );
    }

    /**
     * !Exclusive to sodium_compat!
     *
     * This returns TRUE if the native crypto_pwhash API is available by libsodium.
     * This returns FALSE if only sodium_compat is available.
     *
     * @return bool
     */
    public static function crypto_pwhash_is_available(): bool
    {
        if (self::useNewSodiumAPI()) {
            return true;
        }
        if (self::use_fallback('crypto_pwhash')) {
            return true;
        }
        return false;
    }

    /**
     * @param string $passwd
     * @param int $opslimit
     * @param int $memlimit
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_pwhash_str(
        #[SensitiveParameter]
        string $passwd,
        int $opslimit,
        int $memlimit
    ): string {
        if (self::useNewSodiumAPI()) {
            return sodium_crypto_pwhash_str($passwd, $opslimit, $memlimit);
        }
        if (self::use_fallback('crypto_pwhash_str')) {
            return (string) call_user_func('\\Sodium\\crypto_pwhash_str', $passwd, $opslimit, $memlimit);
        }
        // This is the best we can do.
        throw new SodiumException(
            'This is not implemented, as it is not possible to implement Argon2i with acceptable performance in pure-PHP'
        );
    }

    /**
     * Do we need to rehash this password?
     *
     * @param string $hash
     * @param int $opslimit
     * @param int $memlimit
     * @return bool
     * @throws SodiumException
     */
    public static function crypto_pwhash_str_needs_rehash(
        #[SensitiveParameter]
        string $hash,
        int $opslimit,
        int $memlimit
    ): bool {
        // Just grab the first 4 pieces.
        $pieces = explode('$', $hash);
        $prefix = implode('$', array_slice($pieces, 0, 4));

        // Rebuild the expected header.
        $ops =  $opslimit;
        $mem = $memlimit >> 10;
        $encoded = self::CRYPTO_PWHASH_STRPREFIX . 'v=19$m=' . $mem . ',t=' . $ops . ',p=1';

        // Do they match? If so, we don't need to rehash, so return false.
        return !ParagonIE_Sodium_Core_Util::hashEquals($encoded, $prefix);
    }

    /**
     * @param string $passwd
     * @param string $hash
     * @return bool
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_pwhash_str_verify(
        #[SensitiveParameter]
        string $passwd,
        #[SensitiveParameter]
        string $hash
    ): bool {
        if (self::useNewSodiumAPI()) {
            return sodium_crypto_pwhash_str_verify($passwd, $hash);
        }
        if (self::use_fallback('crypto_pwhash_str_verify')) {
            return (bool) call_user_func('\\Sodium\\crypto_pwhash_str_verify', $passwd, $hash);
        }
        // This is the best we can do.
        throw new SodiumException(
            'This is not implemented, as it is not possible to implement Argon2i with acceptable performance in pure-PHP'
        );
    }

    /**
     * @param int $outlen
     * @param string $passwd
     * @param string $salt
     * @param int $opslimit
     * @param int $memlimit
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_pwhash_scryptsalsa208sha256(
        int $outlen,
        #[SensitiveParameter]
        string $passwd,
        #[SensitiveParameter]
        string $salt,
        int $opslimit,
        int $memlimit
    ): string {
        if (self::useNewSodiumAPI()) {
            return sodium_crypto_pwhash_scryptsalsa208sha256(
                $outlen,
                $passwd,
                $salt,
                $opslimit,
                $memlimit
            );
        }
        if (self::use_fallback('crypto_pwhash_scryptsalsa208sha256')) {
            return (string) call_user_func(
                '\\Sodium\\crypto_pwhash_scryptsalsa208sha256',
                $outlen,
                $passwd,
                $salt,
                $opslimit,
                $memlimit
            );
        }
        // This is the best we can do.
        throw new SodiumException(
            'This is not implemented, as it is not possible to implement Scrypt with acceptable performance in pure-PHP'
        );
    }

    /**
     * !Exclusive to sodium_compat!
     *
     * This returns TRUE if the native crypto_pwhash API is available by libsodium.
     * This returns FALSE if only sodium_compat is available.
     *
     * @return bool
     */
    public static function crypto_pwhash_scryptsalsa208sha256_is_available(): bool
    {
        if (self::useNewSodiumAPI()) {
            return true;
        }
        if (self::use_fallback('crypto_pwhash_scryptsalsa208sha256')) {
            return true;
        }
        return false;
    }

    /**
     * @param string $passwd
     * @param int $opslimit
     * @param int $memlimit
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_pwhash_scryptsalsa208sha256_str(
        #[SensitiveParameter]
        string $passwd,
        int $opslimit,
        int $memlimit
    ): string {
        if (self::useNewSodiumAPI()) {
            return sodium_crypto_pwhash_scryptsalsa208sha256_str(
                $passwd,
                $opslimit,
                $memlimit
            );
        }
        if (self::use_fallback('crypto_pwhash_scryptsalsa208sha256_str')) {
            return (string) call_user_func(
                '\\Sodium\\crypto_pwhash_scryptsalsa208sha256_str',
                $passwd,
                $opslimit,
                $memlimit
            );
        }
        // This is the best we can do.
        throw new SodiumException(
            'This is not implemented, as it is not possible to implement Scrypt with acceptable performance in pure-PHP'
        );
    }

    /**
     * @param string $passwd
     * @param string $hash
     * @return bool
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_pwhash_scryptsalsa208sha256_str_verify(
        #[SensitiveParameter]
        string $passwd,
        #[SensitiveParameter]
        string $hash
    ): bool {
        if (self::useNewSodiumAPI()) {
            return sodium_crypto_pwhash_scryptsalsa208sha256_str_verify($passwd, $hash);
        }
        if (self::use_fallback('crypto_pwhash_scryptsalsa208sha256_str_verify')) {
            return (bool) call_user_func(
                '\\Sodium\\crypto_pwhash_scryptsalsa208sha256_str_verify',
                $passwd,
                $hash
            );
        }
        // This is the best we can do.
        throw new SodiumException(
            'This is not implemented, as it is not possible to implement Scrypt with acceptable performance in pure-PHP'
        );
    }

    /**
     * Calculate the shared secret between your secret key and your
     * recipient's public key.
     *
     * Algorithm: X25519 (ECDH over Curve25519)
     *
     * @param string $secretKey
     * @param string $publicKey
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_scalarmult(
        #[SensitiveParameter]
        string $secretKey,
        string $publicKey
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($secretKey) !== self::CRYPTO_BOX_SECRETKEYBYTES) {
            throw new SodiumException('Argument 1 must be CRYPTO_BOX_SECRETKEYBYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($publicKey) !== self::CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new SodiumException('Argument 2 must be CRYPTO_BOX_PUBLICKEYBYTES long.');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_scalarmult($secretKey, $publicKey);
        }
        if (self::use_fallback('crypto_scalarmult')) {
            return (string) call_user_func('\\Sodium\\crypto_scalarmult', $secretKey, $publicKey);
        }

        /* Output validation: Forbid all-zero keys */
        if (ParagonIE_Sodium_Core_Util::hashEquals($secretKey, str_repeat("\0", self::CRYPTO_BOX_SECRETKEYBYTES))) {
            throw new SodiumException('Zero secret key is not allowed');
        }
        if (ParagonIE_Sodium_Core_Util::hashEquals($publicKey, str_repeat("\0", self::CRYPTO_BOX_PUBLICKEYBYTES))) {
            throw new SodiumException('Zero public key is not allowed');
        }
        return ParagonIE_Sodium_Crypto::scalarmult($secretKey, $publicKey);
    }

    /**
     * Calculate an X25519 public key from an X25519 secret key.
     *
     * @param string $secretKey
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_scalarmult_base(
        #[SensitiveParameter]
        string $secretKey
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($secretKey) !== self::CRYPTO_BOX_SECRETKEYBYTES) {
            throw new SodiumException('Argument 1 must be CRYPTO_BOX_SECRETKEYBYTES long.');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_scalarmult_base($secretKey);
        }
        if (self::use_fallback('crypto_scalarmult_base')) {
            return (string) call_user_func('\\Sodium\\crypto_scalarmult_base', $secretKey);
        }
        if (ParagonIE_Sodium_Core_Util::hashEquals($secretKey, str_repeat("\0", self::CRYPTO_BOX_SECRETKEYBYTES))) {
            throw new SodiumException('Zero secret key is not allowed');
        }
        return ParagonIE_Sodium_Crypto::scalarmult_base($secretKey);
    }

    /**
     * Authenticated symmetric-key encryption.
     *
     * Algorithm: XSalsa20-Poly1305
     *
     * @param string $plaintext The message you're encrypting
     * @param string $nonce A Number to be used Once; must be 24 bytes
     * @param string $key Symmetric encryption key
     * @return string           Ciphertext with Poly1305 MAC
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_secretbox(
        #[SensitiveParameter]
        string $plaintext,
        string $nonce,
        #[SensitiveParameter]
        string $key
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_SECRETBOX_NONCEBYTES) {
            throw new SodiumException('Argument 2 must be CRYPTO_SECRETBOX_NONCEBYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_SECRETBOX_KEYBYTES) {
            throw new SodiumException('Argument 3 must be CRYPTO_SECRETBOX_KEYBYTES long.');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_secretbox($plaintext, $nonce, $key);
        }
        if (self::use_fallback('crypto_secretbox')) {
            return (string) call_user_func('\\Sodium\\crypto_secretbox', $plaintext, $nonce, $key);
        }
        return ParagonIE_Sodium_Crypto::secretbox($plaintext, $nonce, $key);
    }

    /**
     * Decrypts a message previously encrypted with crypto_secretbox().
     *
     * @param string $ciphertext Ciphertext with Poly1305 MAC
     * @param string $nonce      A Number to be used Once; must be 24 bytes
     * @param string $key        Symmetric encryption key
     * @return string|bool       Original plaintext message
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_secretbox_open(
        string $ciphertext,
        string $nonce,
        #[SensitiveParameter]
        string $key
    ): string|bool {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_SECRETBOX_NONCEBYTES) {
            throw new SodiumException('Argument 2 must be CRYPTO_SECRETBOX_NONCEBYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_SECRETBOX_KEYBYTES) {
            throw new SodiumException('Argument 3 must be CRYPTO_SECRETBOX_KEYBYTES long.');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_secretbox_open($ciphertext, $nonce, $key);
        }
        if (self::use_fallback('crypto_secretbox_open')) {
            return call_user_func('\\Sodium\\crypto_secretbox_open', $ciphertext, $nonce, $key);
        }
        return ParagonIE_Sodium_Crypto::secretbox_open($ciphertext, $nonce, $key);
    }

    /**
     * Return a secure random key for use with crypto_secretbox
     *
     * @return string
     * @throws Exception
     * @throws Error
     */
    public static function crypto_secretbox_keygen(): string
    {
        return random_bytes(self::CRYPTO_SECRETBOX_KEYBYTES);
    }

    /**
     * Authenticated symmetric-key encryption.
     *
     * Algorithm: XChaCha20-Poly1305
     *
     * @param string $plaintext The message you're encrypting
     * @param string $nonce     A Number to be used Once; must be 24 bytes
     * @param string $key       Symmetric encryption key
     * @return string           Ciphertext with Poly1305 MAC
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_secretbox_xchacha20poly1305(
        #[SensitiveParameter]
        string $plaintext,
        string $nonce,
        string $key
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_SECRETBOX_NONCEBYTES) {
            throw new SodiumException('Argument 2 must be CRYPTO_SECRETBOX_NONCEBYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_SECRETBOX_KEYBYTES) {
            throw new SodiumException('Argument 3 must be CRYPTO_SECRETBOX_KEYBYTES long.');
        }
        return ParagonIE_Sodium_Crypto::secretbox_xchacha20poly1305($plaintext, $nonce, $key);
    }

    /**
     * Decrypts a message previously encrypted with crypto_secretbox_xchacha20poly1305().
     *
     * @param string $ciphertext Ciphertext with Poly1305 MAC
     * @param string $nonce      A Number to be used Once; must be 24 bytes
     * @param string $key        Symmetric encryption key
     * @return string            Original plaintext message
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_secretbox_xchacha20poly1305_open(
        string $ciphertext,
        string $nonce,
        #[SensitiveParameter]
        string $key
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_SECRETBOX_NONCEBYTES) {
            throw new SodiumException('Argument 2 must be CRYPTO_SECRETBOX_NONCEBYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_SECRETBOX_KEYBYTES) {
            throw new SodiumException('Argument 3 must be CRYPTO_SECRETBOX_KEYBYTES long.');
        }

        return ParagonIE_Sodium_Crypto::secretbox_xchacha20poly1305_open($ciphertext, $nonce, $key);
    }

    /**
     * @param string $key
     * @return array<int, string> Returns a state and a header.
     * @throws Exception
     * @throws SodiumException
     */
    public static function crypto_secretstream_xchacha20poly1305_init_push(
        #[SensitiveParameter]
        string $key
    ): array {
        return ParagonIE_Sodium_Crypto::secretstream_xchacha20poly1305_init_push($key);
    }

    /**
     * @param string $header
     * @param string $key
     * @return string Returns a state.
     * @throws Exception
     */
    public static function crypto_secretstream_xchacha20poly1305_init_pull(
        string $header,
        #[SensitiveParameter]
        string $key
    ): string {
        if (ParagonIE_Sodium_Core_Util::strlen($header) < self::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES) {
            throw new SodiumException(
                'header size should be SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES bytes'
            );
        }
        return ParagonIE_Sodium_Crypto::secretstream_xchacha20poly1305_init_pull($key, $header);
    }

    /**
     * @param string $state
     * @param string $msg
     * @param string $aad
     * @param int $tag
     * @return string
     * @throws SodiumException
     */
    public static function crypto_secretstream_xchacha20poly1305_push(
        #[SensitiveParameter]
        string &$state,
        #[SensitiveParameter]
        string $msg,
        string $aad = '',
        int $tag = 0
    ): string {
        return ParagonIE_Sodium_Crypto::secretstream_xchacha20poly1305_push(
            $state,
            $msg,
            $aad,
            $tag
        );
    }

    /**
     * @param string $state
     * @param string $msg
     * @param string $aad
     * @return bool|array{0: string, 1: int}
     * @throws SodiumException
     */
    public static function crypto_secretstream_xchacha20poly1305_pull(
        #[SensitiveParameter]
        string &$state,
        string $msg,
        string $aad = ''
    ): bool|array {
        return ParagonIE_Sodium_Crypto::secretstream_xchacha20poly1305_pull(
            $state,
            $msg,
            $aad
        );
    }

    /**
     * @return string
     * @throws Exception
     */
    public static function crypto_secretstream_xchacha20poly1305_keygen(): string
    {
        return random_bytes(self::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);
    }

    /**
     * @param string $state
     * @return void
     * @throws SodiumException
     */
    public static function crypto_secretstream_xchacha20poly1305_rekey(
        #[SensitiveParameter]
        string &$state
    ): void {
        ParagonIE_Sodium_Crypto::secretstream_xchacha20poly1305_rekey($state);
    }

    /**
     * Calculates a SipHash-2-4 hash of a message for a given key.
     *
     * @param string $message Input message
     * @param string $key SipHash-2-4 key
     * @return string         Hash
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_shorthash(
        string $message,
        #[SensitiveParameter]
        string $key
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_SHORTHASH_KEYBYTES) {
            throw new SodiumException('Argument 2 must be CRYPTO_SHORTHASH_KEYBYTES long.');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_shorthash($message, $key);
        }
        if (self::use_fallback('crypto_shorthash')) {
            return (string) call_user_func('\\Sodium\\crypto_shorthash', $message, $key);
        }
        return ParagonIE_Sodium_Core_SipHash::sipHash24($message, $key);
    }

    /**
     * Return a secure random key for use with crypto_shorthash
     *
     * @return string
     * @throws Exception
     * @throws Error
     */
    public static function crypto_shorthash_keygen(): string
    {
        return random_bytes(self::CRYPTO_SHORTHASH_KEYBYTES);
    }

    /**
     * Returns a signed message. You probably want crypto_sign_detached()
     * instead, which only returns the signature.
     *
     * Algorithm: Ed25519 (EdDSA over Curve25519)
     *
     * @param string $message Message to be signed.
     * @param string $secretKey Secret signing key.
     * @return string           Signed message (signature is prefixed).
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_sign(
        string $message,
        #[SensitiveParameter]
        string $secretKey
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($secretKey) !== self::CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new SodiumException('Argument 2 must be CRYPTO_SIGN_SECRETKEYBYTES long.');
        }
        if (self::useNewSodiumAPI()) {
            return sodium_crypto_sign($message, $secretKey);
        }
        if (self::use_fallback('crypto_sign')) {
            return (string) call_user_func('\\Sodium\\crypto_sign', $message, $secretKey);
        }
        return ParagonIE_Sodium_Crypto::sign($message, $secretKey);
    }

    /**
     * Validates a signed message then returns the message.
     *
     * @param string $signedMessage A signed message
     * @param string $publicKey A public key
     * @return string|bool          The original message (if the signature is
     *                              valid for this public key)
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_sign_open(string $signedMessage, string $publicKey): string|bool
    {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($signedMessage) < self::CRYPTO_SIGN_BYTES) {
            throw new SodiumException('Argument 1 must be at least CRYPTO_SIGN_BYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($publicKey) !== self::CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new SodiumException('Argument 2 must be CRYPTO_SIGN_PUBLICKEYBYTES long.');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_sign_open($signedMessage, $publicKey);
        }
        if (self::use_fallback('crypto_sign_open')) {
            return call_user_func('\\Sodium\\crypto_sign_open', $signedMessage, $publicKey);
        }
        return ParagonIE_Sodium_Crypto::sign_open($signedMessage, $publicKey);
    }

    /**
     * Generate a new random Ed25519 keypair.
     *
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_sign_keypair(): string
    {
        if (self::useNewSodiumAPI()) {
            return sodium_crypto_sign_keypair();
        }
        if (self::use_fallback('crypto_sign_keypair')) {
            return (string) call_user_func('\\Sodium\\crypto_sign_keypair');
        }
        return ParagonIE_Sodium_Core_Ed25519::keypair();
    }

    /**
     * @param string $sk
     * @param string $pk
     * @return string
     * @throws SodiumException
     */
    public static function crypto_sign_keypair_from_secretkey_and_publickey(
        #[SensitiveParameter]
        string $sk,
        string $pk
    ): string {
        if (ParagonIE_Sodium_Core_Util::strlen($sk) !== self::CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new SodiumException('secretkey should be SODIUM_CRYPTO_SIGN_SECRETKEYBYTES bytes');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($pk) !== self::CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new SodiumException('publickey should be SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES bytes');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_sign_keypair_from_secretkey_and_publickey($sk, $pk);
        }
        return $sk . $pk;
    }

    /**
     * Generate an Ed25519 keypair from a seed.
     *
     * @param string $seed Input seed
     * @return string      Keypair
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_sign_seed_keypair(
        #[SensitiveParameter]
        string $seed
    ): string {
        if (self::useNewSodiumAPI()) {
            return sodium_crypto_sign_seed_keypair($seed);
        }
        if (self::use_fallback('crypto_sign_keypair')) {
            return (string) call_user_func('\\Sodium\\crypto_sign_seed_keypair', $seed);
        }
        $publicKey = '';
        $secretKey = '';
        ParagonIE_Sodium_Core_Ed25519::seed_keypair($publicKey, $secretKey, $seed);
        return $secretKey . $publicKey;
    }

    /**
     * Extract an Ed25519 public key from an Ed25519 keypair.
     *
     * @param string $keypair Keypair
     * @return string         Public key
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_sign_publickey(
        #[SensitiveParameter]
        string $keypair
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($keypair) !== self::CRYPTO_SIGN_KEYPAIRBYTES) {
            throw new SodiumException('Argument 1 must be CRYPTO_SIGN_KEYPAIRBYTES long.');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_sign_publickey($keypair);
        }
        if (self::use_fallback('crypto_sign_publickey')) {
            return (string) call_user_func('\\Sodium\\crypto_sign_publickey', $keypair);
        }
        return ParagonIE_Sodium_Core_Ed25519::publickey($keypair);
    }

    /**
     * Calculate an Ed25519 public key from an Ed25519 secret key.
     *
     * @param string $secretKey Your Ed25519 secret key
     * @return string           The corresponding Ed25519 public key
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_sign_publickey_from_secretkey(
        #[SensitiveParameter]
        string $secretKey
    ): string {

        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($secretKey) !== self::CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new SodiumException('Argument 1 must be CRYPTO_SIGN_SECRETKEYBYTES long.');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_sign_publickey_from_secretkey($secretKey);
        }
        if (self::use_fallback('crypto_sign_publickey_from_secretkey')) {
            return (string) call_user_func('\\Sodium\\crypto_sign_publickey_from_secretkey', $secretKey);
        }
        return ParagonIE_Sodium_Core_Ed25519::publickey_from_secretkey($secretKey);
    }

    /**
     * Extract an Ed25519 secret key from an Ed25519 keypair.
     *
     * @param string $keypair Keypair
     * @return string         Secret key
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_sign_secretkey(
        #[SensitiveParameter]
        string $keypair
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($keypair) !== self::CRYPTO_SIGN_KEYPAIRBYTES) {
            throw new SodiumException('Argument 1 must be CRYPTO_SIGN_KEYPAIRBYTES long.');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_sign_secretkey($keypair);
        }
        if (self::use_fallback('crypto_sign_secretkey')) {
            return (string) call_user_func('\\Sodium\\crypto_sign_secretkey', $keypair);
        }
        return ParagonIE_Sodium_Core_Ed25519::secretkey($keypair);
    }

    /**
     * Calculate the Ed25519 signature of a message and return ONLY the signature.
     *
     * Algorithm: Ed25519 (EdDSA over Curve25519)
     *
     * @param string $message Message to be signed
     * @param string $secretKey Secret signing key
     * @return string           Digital signature
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_sign_detached(
        string $message,
        #[SensitiveParameter]
        string $secretKey
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($secretKey) !== self::CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new SodiumException('Argument 2 must be CRYPTO_SIGN_SECRETKEYBYTES long.');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_sign_detached($message, $secretKey);
        }
        if (self::use_fallback('crypto_sign_detached')) {
            return (string) call_user_func('\\Sodium\\crypto_sign_detached', $message, $secretKey);
        }
        return ParagonIE_Sodium_Crypto::sign_detached($message, $secretKey);
    }

    /**
     * Verify the Ed25519 signature of a message.
     *
     * @param string $signature Digital sginature
     * @param string $message Message to be verified
     * @param string $publicKey Public key
     * @return bool             TRUE if this signature is good for this public key;
     *                          FALSE otherwise
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_sign_verify_detached(
        string $signature,
        string $message,
        string $publicKey
    ): bool {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($signature) !== self::CRYPTO_SIGN_BYTES) {
            throw new SodiumException('Argument 1 must be CRYPTO_SIGN_BYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($publicKey) !== self::CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new SodiumException('Argument 3 must be CRYPTO_SIGN_PUBLICKEYBYTES long.');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_sign_verify_detached($signature, $message, $publicKey);
        }
        if (self::use_fallback('crypto_sign_verify_detached')) {
            return (bool) call_user_func(
                '\\Sodium\\crypto_sign_verify_detached',
                $signature,
                $message,
                $publicKey
            );
        }
        return ParagonIE_Sodium_Crypto::sign_verify_detached($signature, $message, $publicKey);
    }

    /**
     * Convert an Ed25519 public key to a Curve25519 public key
     *
     * @param string $pk
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_sign_ed25519_pk_to_curve25519(string $pk): string
    {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($pk) < self::CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new SodiumException('Argument 1 must be at least CRYPTO_SIGN_PUBLICKEYBYTES long.');
        }
        if (self::useNewSodiumAPI()) {
            if (is_callable('crypto_sign_ed25519_pk_to_curve25519')) {
                return sodium_crypto_sign_ed25519_pk_to_curve25519($pk);
            }
        }
        if (self::use_fallback('crypto_sign_ed25519_pk_to_curve25519')) {
            return (string) call_user_func('\\Sodium\\crypto_sign_ed25519_pk_to_curve25519', $pk);
        }
        return ParagonIE_Sodium_Core_Ed25519::pk_to_curve25519($pk);
    }

    /**
     * Convert an Ed25519 secret key to a Curve25519 secret key
     *
     * @param string $sk
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_sign_ed25519_sk_to_curve25519(
        #[SensitiveParameter]
        string $sk
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($sk) < self::CRYPTO_SIGN_SEEDBYTES) {
            throw new SodiumException('Argument 1 must be at least CRYPTO_SIGN_SEEDBYTES long.');
        }
        if (self::useNewSodiumAPI()) {
            if (is_callable('crypto_sign_ed25519_sk_to_curve25519')) {
                return sodium_crypto_sign_ed25519_sk_to_curve25519($sk);
            }
        }
        if (self::use_fallback('crypto_sign_ed25519_sk_to_curve25519')) {
            return (string) call_user_func('\\Sodium\\crypto_sign_ed25519_sk_to_curve25519', $sk);
        }

        $h = hash('sha512', ParagonIE_Sodium_Core_Util::substr($sk, 0, 32), true);
        $h[0] = ParagonIE_Sodium_Core_Util::intToChr(
            ParagonIE_Sodium_Core_Util::chrToInt($h[0]) & 248
        );
        $h[31] = ParagonIE_Sodium_Core_Util::intToChr(
            (ParagonIE_Sodium_Core_Util::chrToInt($h[31]) & 127) | 64
        );
        return ParagonIE_Sodium_Core_Util::substr($h, 0, 32);
    }

    /**
     * Expand a key and nonce into a keystream of pseudorandom bytes.
     *
     * @param int $len Number of bytes desired
     * @param string $nonce Number to be used Once; must be 24 bytes
     * @param string $key XSalsa20 key
     * @return string       Pseudorandom stream that can be XORed with messages
     *                      to provide encryption (but not authentication; see
     *                      Poly1305 or crypto_auth() for that, which is not
     *                      optional for security)
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_stream(
        int $len,
        string $nonce,
        #[SensitiveParameter]
        string $key
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_STREAM_NONCEBYTES) {
            throw new SodiumException('Argument 2 must be CRYPTO_SECRETBOX_NONCEBYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_STREAM_KEYBYTES) {
            throw new SodiumException('Argument 3 must be CRYPTO_STREAM_KEYBYTES long.');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_stream($len, $nonce, $key);
        }
        if (self::use_fallback('crypto_stream')) {
            return (string) call_user_func('\\Sodium\\crypto_stream', $len, $nonce, $key);
        }
        return ParagonIE_Sodium_Core_XSalsa20::xsalsa20($len, $nonce, $key);
    }

    /**
     * DANGER! UNAUTHENTICATED ENCRYPTION!
     *
     * Unless you are following expert advice, do not use this feature.
     *
     * Algorithm: XSalsa20
     *
     * This DOES NOT provide ciphertext integrity.
     *
     * @param string $message Plaintext message
     * @param string $nonce Number to be used Once; must be 24 bytes
     * @param string $key Encryption key
     * @return string         Encrypted text which is vulnerable to chosen-
     *                        ciphertext attacks unless you implement some
     *                        other mitigation to the ciphertext (i.e.
     *                        Encrypt then MAC)
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_stream_xor(
        #[SensitiveParameter]
        string $message,
        string $nonce,
        #[SensitiveParameter]
        string $key
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_STREAM_NONCEBYTES) {
            throw new SodiumException('Argument 2 must be CRYPTO_SECRETBOX_NONCEBYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_STREAM_KEYBYTES) {
            throw new SodiumException('Argument 3 must be CRYPTO_SECRETBOX_KEYBYTES long.');
        }

        if (self::useNewSodiumAPI()) {
            return sodium_crypto_stream_xor($message, $nonce, $key);
        }
        if (self::use_fallback('crypto_stream_xor')) {
            return (string) call_user_func('\\Sodium\\crypto_stream_xor', $message, $nonce, $key);
        }
        return ParagonIE_Sodium_Core_XSalsa20::xsalsa20_xor($message, $nonce, $key);
    }

    /**
     * Return a secure random key for use with crypto_stream
     *
     * @return string
     * @throws Exception
     * @throws Error
     */
    public static function crypto_stream_keygen(): string
    {
        return random_bytes(self::CRYPTO_STREAM_KEYBYTES);
    }

    /**
     * Expand a key and nonce into a keystream of pseudorandom bytes.
     *
     * @param int $len Number of bytes desired
     * @param string $nonce Number to be used Once; must be 24 bytes
     * @param string $key XChaCha20 key
     * @param bool $dontFallback
     * @return string       Pseudorandom stream that can be XORed with messages
     *                      to provide encryption (but not authentication; see
     *                      Poly1305 or crypto_auth() for that, which is not
     *                      optional for security)
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_stream_xchacha20(
        int $len,
        string $nonce,
        #[SensitiveParameter]
        string $key,
        bool $dontFallback = false
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_STREAM_XCHACHA20_NONCEBYTES) {
            throw new SodiumException('Argument 2 must be CRYPTO_SECRETBOX_XCHACHA20_NONCEBYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_STREAM_XCHACHA20_KEYBYTES) {
            throw new SodiumException('Argument 3 must be CRYPTO_STREAM_XCHACHA20_KEYBYTES long.');
        }

        if (self::useNewSodiumAPI() && !$dontFallback) {
            return sodium_crypto_stream_xchacha20($len, $nonce, $key);
        }
        return ParagonIE_Sodium_Core_XChaCha20::stream($len, $nonce, $key);
    }

    /**
     * DANGER! UNAUTHENTICATED ENCRYPTION!
     *
     * Unless you are following expert advice, do not use this feature.
     *
     * Algorithm: XChaCha20
     *
     * This DOES NOT provide ciphertext integrity.
     *
     * @param string $message Plaintext message
     * @param string $nonce Number to be used Once; must be 24 bytes
     * @param string $key Encryption key
     * @return string         Encrypted text which is vulnerable to chosen-
     *                        ciphertext attacks unless you implement some
     *                        other mitigation to the ciphertext (i.e.
     *                        Encrypt then MAC)
     * @param bool $dontFallback
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_stream_xchacha20_xor(
        #[SensitiveParameter]
        string $message,
        string $nonce,
        #[SensitiveParameter]
        string $key,
        bool $dontFallback = false
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_STREAM_XCHACHA20_NONCEBYTES) {
            throw new SodiumException('Argument 2 must be CRYPTO_SECRETBOX_XCHACHA20_NONCEBYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_STREAM_XCHACHA20_KEYBYTES) {
            throw new SodiumException('Argument 3 must be CRYPTO_SECRETBOX_XCHACHA20_KEYBYTES long.');
        }

        if (self::useNewSodiumAPI() && !$dontFallback) {
            return sodium_crypto_stream_xchacha20_xor($message, $nonce, $key);
        }
        return ParagonIE_Sodium_Core_XChaCha20::streamXorIc($message, $nonce, $key);
    }

    /**
     * DANGER! UNAUTHENTICATED ENCRYPTION!
     *
     * Unless you are following expert advice, do not use this feature.
     *
     * Algorithm: XChaCha20
     *
     * This DOES NOT provide ciphertext integrity.
     *
     * @param string $message Plaintext message
     * @param string $nonce Number to be used Once; must be 24 bytes
     * @param int $counter
     * @param string $key Encryption key
     * @return string         Encrypted text which is vulnerable to chosen-
     *                        ciphertext attacks unless you implement some
     *                        other mitigation to the ciphertext (i.e.
     *                        Encrypt then MAC)
     * @param bool $dontFallback
     * @throws SodiumException
     * @throws TypeError
     */
    public static function crypto_stream_xchacha20_xor_ic(
        #[SensitiveParameter]
        string $message,
        string $nonce,
        int $counter,
        #[SensitiveParameter]
        string $key,
        bool $dontFallback = false
    ): string {
        /* Input validation: */
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_STREAM_XCHACHA20_NONCEBYTES) {
            throw new SodiumException('Argument 2 must be CRYPTO_SECRETBOX_XCHACHA20_NONCEBYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_STREAM_XCHACHA20_KEYBYTES) {
            throw new SodiumException('Argument 3 must be CRYPTO_SECRETBOX_XCHACHA20_KEYBYTES long.');
        }

        if (is_callable('sodium_crypto_stream_xchacha20_xor_ic') && !$dontFallback) {
            return sodium_crypto_stream_xchacha20_xor_ic($message, $nonce, $counter, $key);
        }

        $ic = ParagonIE_Sodium_Core_Util::store64_le($counter);
        return ParagonIE_Sodium_Core_XChaCha20::streamXorIc($message, $nonce, $key, $ic);
    }

    /**
     * Return a secure random key for use with crypto_stream_xchacha20
     *
     * @return string
     * @throws Exception
     * @throws Error
     */
    public static function crypto_stream_xchacha20_keygen(): string
    {
        return random_bytes(self::CRYPTO_STREAM_XCHACHA20_KEYBYTES);
    }

    /**
     * Cache-timing-safe implementation of hex2bin().
     *
     * @param string $string Hexadecimal string
     * @param string $ignore List of characters to ignore; useful for whitespace
     * @return string        Raw binary string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function hex2bin(
        #[SensitiveParameter]
        string $string,
        string $ignore = ''
    ): string {
        if (self::useNewSodiumAPI()) {
            if (is_callable('sodium_hex2bin')) {
                return sodium_hex2bin($string, $ignore);
            }
        }
        if (self::use_fallback('hex2bin')) {
            return (string) call_user_func('\\Sodium\\hex2bin', $string, $ignore);
        }
        return ParagonIE_Sodium_Core_Util::hex2bin($string, $ignore);
    }

    /**
     * Increase a string (little endian)
     *
     * @param string $var
     *
     * @return void
     * @throws SodiumException
     * @throws TypeError
     */
    public static function increment(
        #[SensitiveParameter]
        string &$var
    ): void {
        if (self::useNewSodiumAPI()) {
            sodium_increment($var);
            return;
        }
        if (self::use_fallback('increment')) {
            $func = '\\Sodium\\increment';
            $func($var);
            return;
        }

        $len = ParagonIE_Sodium_Core_Util::strlen($var);
        $c = 1;
        $copy = '';
        for ($i = 0; $i < $len; ++$i) {
            $c += ParagonIE_Sodium_Core_Util::chrToInt(
                ParagonIE_Sodium_Core_Util::substr($var, $i, 1)
            );
            $copy .= ParagonIE_Sodium_Core_Util::intToChr($c);
            $c >>= 8;
        }
        $var = $copy;
    }

    /**
     * @param string $str
     * @return bool
     *
     * @throws SodiumException
     */
    public static function is_zero(
        #[SensitiveParameter]
        string $str
    ): bool {
        $d = 0;
        for ($i = 0; $i < 32; ++$i) {
            $d |= ParagonIE_Sodium_Core_Util::chrToInt($str[$i]);
        }
        return ((($d - 1) >> 31) & 1) === 1;
    }

    /**
     * The equivalent to the libsodium minor version we aim to be compatible
     * with (sans pwhash and memzero).
     *
     * @return int
     */
    public static function library_version_major(): int
    {
        if (self::useNewSodiumAPI() && defined('SODIUM_LIBRARY_MAJOR_VERSION')) {
            return SODIUM_LIBRARY_MAJOR_VERSION;
        }
        if (self::use_fallback('library_version_major')) {
            /** @psalm-suppress UndefinedFunction */
            return (int) call_user_func('\\Sodium\\library_version_major');
        }
        return self::LIBRARY_VERSION_MAJOR;
    }

    /**
     * The equivalent to the libsodium minor version we aim to be compatible
     * with (sans pwhash and memzero).
     *
     * @return int
     */
    public static function library_version_minor(): int
    {
        if (self::useNewSodiumAPI() && defined('SODIUM_LIBRARY_MINOR_VERSION')) {
            return SODIUM_LIBRARY_MINOR_VERSION;
        }
        if (self::use_fallback('library_version_minor')) {
            /** @psalm-suppress UndefinedFunction */
            return (int) call_user_func('\\Sodium\\library_version_minor');
        }
        return self::LIBRARY_VERSION_MINOR;
    }

    /**
     * Compare two strings.
     *
     * @param string $left
     * @param string $right
     * @return int
     * @throws SodiumException
     * @throws TypeError
     */
    public static function memcmp(
        #[SensitiveParameter]
        string $left,
        #[SensitiveParameter]
        string $right
    ): int {
        if (self::useNewSodiumAPI()) {
            return sodium_memcmp($left, $right);
        }
        if (self::use_fallback('memcmp')) {
            return (int) call_user_func('\\Sodium\\memcmp', $left, $right);
        }
        return ParagonIE_Sodium_Core_Util::memcmp($left, $right);
    }

    /**
     * It's actually not possible to zero memory buffers in PHP. You need the
     * native library for that.
     *
     * @param ?string $var
     * @param-out string|null $var
     *
     * @return void
     * @throws SodiumException (Unless libsodium is installed)
     * @throws TypeError
     * @psalm-suppress TooFewArguments
     */
    public static function memzero(
        #[SensitiveParameter]
        ?string &$var
    ): void {
        if (is_null($var)) {
            return;
        }
        if (self::useNewSodiumAPI()) {
            /** @psalm-suppress MixedArgument */
            sodium_memzero($var);
            return;
        }
        if (self::use_fallback('memzero')) {
            $func = '\\Sodium\\memzero';
            $func($var);
            return;
        }
        // This is the best we can do.
        throw new SodiumException(
            'This is not implemented in sodium_compat, as it is not possible to securely wipe memory from PHP. ' .
            'To fix this error, make sure libsodium is installed and the PHP extension is enabled.'
        );
    }

    /**
     * @param string $unpadded
     * @param int $blockSize
     * @param bool $dontFallback
     * @return string
     * @throws SodiumException
     */
    public static function pad(
        #[SensitiveParameter]
        string $unpadded,
        int $blockSize,
        bool $dontFallback = false
    ): string {
        if (self::useNewSodiumAPI() && !$dontFallback) {
            return sodium_pad($unpadded, $blockSize);
        }

        if ($blockSize <= 0) {
            throw new SodiumException(
                'block size cannot be less than 1'
            );
        }
        $unpadded_len = ParagonIE_Sodium_Core_Util::strlen($unpadded);
        $xpadlen = ($blockSize - 1);
        if (($blockSize & ($blockSize - 1)) === 0) {
            $xpadlen -= $unpadded_len & ($blockSize - 1);
        } else {
            $xpadlen -= $unpadded_len % $blockSize;
        }

        $xpadded_len = $unpadded_len + $xpadlen;
        $padded = str_repeat("\0", $xpadded_len - 1);
        if ($unpadded_len > 0) {
            $st = 1;
            $i = 0;
            $k = $unpadded_len;
            for ($j = 0; $j <= $xpadded_len; ++$j) {
                $i = (int) $i;
                /** @psalm-suppress RedundantCast */
                $k = (int) $k;
                if ($j >= $unpadded_len) {
                    $padded[$j] = "\0";
                } else {
                    $padded[$j] = $unpadded[$j];
                }
                $k -= $st;
                $st = (~(
                            (
                                (
                                    ($k >> 48)
                                        |
                                    ($k >> 32)
                                        |
                                    ($k >> 16)
                                        |
                                    $k
                                ) - 1
                            ) >> 16
                        )
                    ) & 1;
                $i += $st;
            }
        }

        $mask = 0;
        $tail = $xpadded_len;
        for ($i = 0; $i < $blockSize; ++$i) {
            # barrier_mask = (unsigned char)
            #     (((i ^ xpadlen) - 1U) >> ((sizeof(size_t) - 1U) * CHAR_BIT));
            $barrier_mask = (($i ^ $xpadlen) -1) >> ((PHP_INT_SIZE << 3) - 1);
            # tail[-i] = (tail[-i] & mask) | (0x80 & barrier_mask);
            $padded[$tail - $i] = ParagonIE_Sodium_Core_Util::intToChr(
                (ParagonIE_Sodium_Core_Util::chrToInt($padded[$tail - $i]) & $mask)
                    |
                (0x80 & $barrier_mask)
            );
            # mask |= barrier_mask;
            $mask |= $barrier_mask;
        }
        return $padded;
    }

    /**
     * @param string $padded
     * @param int $blockSize
     * @param bool $dontFallback
     * @return string
     * @throws SodiumException
     */
    public static function unpad(
        #[SensitiveParameter]
        string $padded,
        int $blockSize,
        bool $dontFallback = false
    ): string {
        if (self::useNewSodiumAPI() && !$dontFallback) {
            return sodium_unpad($padded, $blockSize);
        }
        if ($blockSize <= 0) {
            throw new SodiumException('block size cannot be less than 1');
        }
        $padded_len = ParagonIE_Sodium_Core_Util::strlen($padded);
        if ($padded_len < $blockSize) {
            throw new SodiumException('invalid padding');
        }

        # tail = &padded[padded_len - 1U];
        $tail = $padded_len - 1;

        $acc = 0;
        $valid = 0;
        $pad_len = 0;

        $found = 0;
        for ($i = 0; $i < $blockSize; ++$i) {
            # c = tail[-i];
            $c = ParagonIE_Sodium_Core_Util::chrToInt($padded[$tail - $i]);

            # is_barrier =
            #     (( (acc - 1U) & (pad_len - 1U) & ((c ^ 0x80) - 1U) ) >> 8) & 1U;
            $is_barrier = (
                (
                    ($acc - 1) & ($pad_len - 1) & (($c ^ 80) - 1)
                ) >> 7
            ) & 1;
            $is_barrier &= ~$found;
            $found |= $is_barrier;

            # acc |= c;
            $acc |= $c;

            # pad_len |= i & (1U + ~is_barrier);
            $pad_len |= $i & (1 + ~$is_barrier);

            # valid |= (unsigned char) is_barrier;
            $valid |= ($is_barrier & 0xff);
        }
        # unpadded_len = padded_len - 1U - pad_len;
        $unpadded_len = $padded_len - 1 - $pad_len;
        if ($valid !== 1) {
            throw new SodiumException('invalid padding');
        }
        return ParagonIE_Sodium_Core_Util::substr($padded, 0, $unpadded_len);
    }

    /**
     * Will sodium_compat run fast on the current hardware and PHP configuration?
     *
     * @return bool
     */
    public static function polyfill_is_fast(): bool
    {
        if (extension_loaded('sodium')) {
            return true;
        }
        if (extension_loaded('libsodium')) {
            return true;
        }
        return PHP_INT_SIZE === 8;
    }

    /**
     * Generate a string of bytes from the kernel's CSPRNG.
     * Proudly uses /dev/urandom (if getrandom(2) is not available).
     *
     * @param int $numBytes
     * @return string
     * @throws Exception
     * @throws TypeError
     */
    public static function randombytes_buf(int $numBytes): string
    {
        /** @var positive-int $numBytes */
        if (self::use_fallback('randombytes_buf')) {
            return (string) call_user_func('\\Sodium\\randombytes_buf', $numBytes);
        }
        return random_bytes($numBytes);
    }

    /**
     * Generate an integer between 0 and $range (non-inclusive).
     *
     * @param int $range
     * @return int
     * @throws Exception
     * @throws Error
     * @throws TypeError
     */
    public static function randombytes_uniform(int $range): int
    {
        if (self::use_fallback('randombytes_uniform')) {
            return (int) call_user_func('\\Sodium\\randombytes_uniform', $range);
        }
        return random_int(0, $range - 1);
    }

    /**
     * Generate a random 16-bit integer.
     *
     * @return int
     * @throws Exception
     * @throws Error
     * @throws TypeError
     */
    public static function randombytes_random16(): int
    {
        if (self::use_fallback('randombytes_random16')) {
            return (int) call_user_func('\\Sodium\\randombytes_random16');
        }
        return random_int(0, 65535);
    }

    /**
     * @param string $p
     * @param bool $dontFallback
     * @return bool
     * @throws SodiumException
     */
    public static function ristretto255_is_valid_point(
        string $p,
        bool $dontFallback = false
    ): bool {
        if (self::useNewSodiumAPI() && !$dontFallback) {
            return sodium_crypto_core_ristretto255_is_valid_point($p);
        }
        try {
            $r = ParagonIE_Sodium_Core_Ristretto255::ristretto255_frombytes($p);
            return $r['res'] === 0 &&
                ParagonIE_Sodium_Core_Ristretto255::ristretto255_point_is_canonical($p) === 1;
        } catch (SodiumException $ex) {
            if ($ex->getMessage() === 'S is not canonical') {
                return false;
            }
            throw $ex;
        }
    }

    /**
     * @param string $p
     * @param string $q
     * @param bool $dontFallback
     * @return string
     * @throws SodiumException
     */
    public static function ristretto255_add(
        #[SensitiveParameter]
        string $p,
        #[SensitiveParameter]
        string $q,
        bool $dontFallback = false
    ): string {
        if (self::useNewSodiumAPI() && !$dontFallback) {
            return sodium_crypto_core_ristretto255_add($p, $q);
        }
        return ParagonIE_Sodium_Core_Ristretto255::ristretto255_add($p, $q);
    }

    /**
     * @param string $p
     * @param string $q
     * @param bool $dontFallback
     * @return string
     * @throws SodiumException
     */
    public static function ristretto255_sub(
        #[SensitiveParameter]
        string $p,
        #[SensitiveParameter]
        string $q,
        bool $dontFallback = false
    ): string{
        if (self::useNewSodiumAPI() && !$dontFallback) {
            return sodium_crypto_core_ristretto255_sub($p, $q);
        }
        return ParagonIE_Sodium_Core_Ristretto255::ristretto255_sub($p, $q);
    }

    /**
     * @param string $r
     * @param bool $dontFallback
     * @return string
     *
     * @throws SodiumException
     */
    public static function ristretto255_from_hash(
        #[SensitiveParameter]
        string $r,
        bool $dontFallback = false
    ): string {
        if (self::useNewSodiumAPI() && !$dontFallback) {
            return sodium_crypto_core_ristretto255_from_hash($r);
        }
        return ParagonIE_Sodium_Core_Ristretto255::ristretto255_from_hash($r);
    }

    /**
     * @param bool $dontFallback
     * @return string
     *
     * @throws SodiumException
     */
    public static function ristretto255_random(bool $dontFallback = false): string
    {
        if (self::useNewSodiumAPI() && !$dontFallback) {
            return sodium_crypto_core_ristretto255_random();
        }
        return ParagonIE_Sodium_Core_Ristretto255::ristretto255_random();
    }

    /**
     * @param bool $dontFallback
     * @return string
     *
     * @throws SodiumException
     */
    public static function ristretto255_scalar_random(bool $dontFallback = false): string
    {
        if (self::useNewSodiumAPI() && !$dontFallback) {
            return sodium_crypto_core_ristretto255_scalar_random();
        }
        return ParagonIE_Sodium_Core_Ristretto255::ristretto255_scalar_random();
    }

    /**
     * @param string $s
     * @param bool $dontFallback
     * @return string
     * @throws SodiumException
     */
    public static function ristretto255_scalar_invert(
        #[SensitiveParameter]
        string $s,
        bool $dontFallback = false
    ): string {
        if (self::useNewSodiumAPI() && !$dontFallback) {
            return sodium_crypto_core_ristretto255_scalar_invert($s);
        }
        return ParagonIE_Sodium_Core_Ristretto255::ristretto255_scalar_invert($s);
    }
    /**
     * @param string $s
     * @param bool $dontFallback
     * @return string
     * @throws SodiumException
     */
    public static function ristretto255_scalar_negate(
        #[SensitiveParameter]
        string $s,
        bool $dontFallback = false
    ): string {
        if (self::useNewSodiumAPI() && !$dontFallback) {
            return sodium_crypto_core_ristretto255_scalar_negate($s);
        }
        return ParagonIE_Sodium_Core_Ristretto255::ristretto255_scalar_negate($s);
    }

    /**
     * @param string $s
     * @param bool $dontFallback
     * @return string
     * @throws SodiumException
     */
    public static function ristretto255_scalar_complement(
        #[SensitiveParameter]
        string $s,
        bool $dontFallback = false
    ): string {
        if (self::useNewSodiumAPI() && !$dontFallback) {
            return sodium_crypto_core_ristretto255_scalar_complement($s);
        }
        return ParagonIE_Sodium_Core_Ristretto255::ristretto255_scalar_complement($s);
    }

    /**
     * @param string $x
     * @param string $y
     * @param bool $dontFallback
     * @return string
     * @throws SodiumException
     */
    public static function ristretto255_scalar_add(
        #[SensitiveParameter]
        string $x,
        #[SensitiveParameter]
        string $y,
        bool $dontFallback = false
    ): string {
        if (self::useNewSodiumAPI() && !$dontFallback) {
            return sodium_crypto_core_ristretto255_scalar_add($x, $y);
        }
        return ParagonIE_Sodium_Core_Ristretto255::ristretto255_scalar_add($x, $y);
    }

    /**
     * @param string $x
     * @param string $y
     * @param bool $dontFallback
     * @return string
     * @throws SodiumException
     */
    public static function ristretto255_scalar_sub(
        #[SensitiveParameter]
        string $x,
        #[SensitiveParameter]
        string $y,
        bool $dontFallback = false
    ): string {
        if (self::useNewSodiumAPI() && !$dontFallback) {
            return sodium_crypto_core_ristretto255_scalar_sub($x, $y);
        }
        return ParagonIE_Sodium_Core_Ristretto255::ristretto255_scalar_sub($x, $y);
    }

    /**
     * @param string $x
     * @param string $y
     * @param bool $dontFallback
     * @return string
     * @throws SodiumException
     */
    public static function ristretto255_scalar_mul(
        #[SensitiveParameter]
        string $x,
        #[SensitiveParameter]
        string $y,
        bool $dontFallback = false
    ): string {
        if (self::useNewSodiumAPI() && !$dontFallback) {
            return sodium_crypto_core_ristretto255_scalar_mul($x, $y);
        }
        return ParagonIE_Sodium_Core_Ristretto255::ristretto255_scalar_mul($x, $y);
    }

    /**
     * @param string $n
     * @param string $p
     * @param bool $dontFallback
     * @return string
     * @throws SodiumException
     */
    public static function scalarmult_ristretto255(
        #[SensitiveParameter]
        string $n,
        #[SensitiveParameter]
        string $p,
        bool $dontFallback = false
    ): string {
        if (self::useNewSodiumAPI() && !$dontFallback) {
            return sodium_crypto_scalarmult_ristretto255($n, $p);
        }
        return ParagonIE_Sodium_Core_Ristretto255::scalarmult_ristretto255($n, $p);
    }

    /**
     * @param string $n
     * @param bool $dontFallback
     * @return string
     * @throws SodiumException
     */
    public static function scalarmult_ristretto255_base(
        #[SensitiveParameter]
        string $n,
        bool $dontFallback = false
    ): string {
        if (self::useNewSodiumAPI() && !$dontFallback) {
            return sodium_crypto_scalarmult_ristretto255_base($n);
        }
        return ParagonIE_Sodium_Core_Ristretto255::scalarmult_ristretto255_base($n);
    }

    /**
     * @param string $s
     * @param bool $dontFallback
     * @return string
     * @throws SodiumException
     */
    public static function ristretto255_scalar_reduce(
        #[SensitiveParameter]
        string $s,
        bool $dontFallback = false
    ): string {
        if (self::useNewSodiumAPI() && !$dontFallback) {
            return sodium_crypto_core_ristretto255_scalar_reduce($s);
        }
        return ParagonIE_Sodium_Core_Ristretto255::sc_reduce($s);
    }

    /**
     * Add two numbers (little-endian unsigned), storing the value in the first
     * parameter.
     *
     * This mutates $val.
     *
     * @param string $val
     * @param string $addv
     * @return void
     * @throws SodiumException
     */
    public static function sub(
        #[SensitiveParameter]
        string &$val,
        #[SensitiveParameter]
        string $addv
    ): void {
        $val_len = ParagonIE_Sodium_Core_Util::strlen($val);
        $addv_len = ParagonIE_Sodium_Core_Util::strlen($addv);
        if ($val_len !== $addv_len) {
            throw new SodiumException('values must have the same length');
        }
        $A = ParagonIE_Sodium_Core_Util::stringToIntArray($val);
        $B = ParagonIE_Sodium_Core_Util::stringToIntArray($addv);

        $c = 0;
        for ($i = 0; $i < $val_len; $i++) {
            $c = ($A[$i] - $B[$i] - $c);
            $A[$i] = ($c & 0xff);
            $c = ($c >> 8) & 1;
        }
        $val = ParagonIE_Sodium_Core_Util::intArrayToString($A);
    }

    /**
     * This emulates libsodium's version_string() function, except ours is
     * prefixed with 'polyfill-'.
     *
     * @return string
     * @psalm-suppress MixedInferredReturnType
     * @psalm-suppress UndefinedFunction
     */
    public static function version_string(): string
    {
        if (self::useNewSodiumAPI()) {
            return sodium_version_string();
        }
        if (self::use_fallback('version_string')) {
            return (string) call_user_func('\\Sodium\\version_string');
        }
        return self::VERSION_STRING;
    }

    /**
     * Should we use the libsodium core function instead?
     * This is always a good idea, if it's available. (Unless we're in the
     * middle of running our unit test suite.)
     *
     * If ext/libsodium is available, use it. Return TRUE.
     * Otherwise, we have to use the code provided herein. Return FALSE.
     *
     * @param string $sodium_func_name
     *
     * @return bool
     */
    protected static function use_fallback(string $sodium_func_name = ''): bool
    {
        static $res = null;
        if ($res === null) {
            $res = extension_loaded('libsodium') && PHP_VERSION_ID >= 50300;
        }
        if ($res === false) {
            // No libsodium installed
            return false;
        }
        if (self::$disableFallbackForUnitTests) {
            // Don't fallback. Use the PHP implementation.
            return false;
        }
        if (!empty($sodium_func_name)) {
            return is_callable('\\Sodium\\' . $sodium_func_name);
        }
        return true;
    }

    /**
     * Libsodium as implemented in PHP 7.2
     * and/or ext/sodium (via PECL)
     *
     * @ref https://wiki.php.net/rfc/libsodium
     * @return bool
     */
    protected static function useNewSodiumAPI(): bool
    {
        static $res = null;
        if ($res === null) {
            $res = PHP_VERSION_ID >= 70000 && extension_loaded('sodium');
        }
        if (self::$disableFallbackForUnitTests) {
            // Don't fallback. Use the PHP implementation.
            return false;
        }
        return (bool) $res;
    }
}
