<?php

/**
 * Libsodium compatibility layer
 */
class ParagonIE_Sodium_Compat
{
    /**
     * @var bool
     */
    public static $disableFallbackForUnitTests = false;

    const LIBRARY_VERSION_MAJOR = 9;
    const LIBRARY_VERSION_MINOR = 1;
    const VERSION_STRING = 'polyfill-1.0.8';

    // From libsodium
    const CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES = 32;
    const CRYPTO_AEAD_CHACHA20POLY1305_NSECBYTES = 0;
    const CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES = 8;
    const CRYPTO_AEAD_CHACHA20POLY1305_ABYTES = 16;
    const CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES = 32;
    const CRYPTO_AEAD_CHACHA20POLY1305_IETF_NSECBYTES = 0;
    const CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES = 12;
    const CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES = 16;
    const CRYPTO_AUTH_BYTES = 32;
    const CRYPTO_AUTH_KEYBYTES = 32;
    const CRYPTO_BOX_SEALBYTES = 16;
    const CRYPTO_BOX_SECRETKEYBYTES = 32;
    const CRYPTO_BOX_PUBLICKEYBYTES = 32;
    const CRYPTO_BOX_KEYPAIRBYTES = 64;
    const CRYPTO_BOX_MACBYTES = 16;
    const CRYPTO_BOX_NONCEBYTES = 24;
    const CRYPTO_BOX_SEEDBYTES = 32;
    const CRYPTO_KX_BYTES = 32;
    const CRYPTO_KX_PUBLICKEYBYTES = 32;
    const CRYPTO_KX_SECRETKEYBYTES = 32;
    const CRYPTO_GENERICHASH_BYTES = 32;
    const CRYPTO_GENERICHASH_BYTES_MIN = 16;
    const CRYPTO_GENERICHASH_BYTES_MAX = 64;
    const CRYPTO_GENERICHASH_KEYBYTES = 32;
    const CRYPTO_GENERICHASH_KEYBYTES_MIN = 16;
    const CRYPTO_GENERICHASH_KEYBYTES_MAX = 64;
    const CRYPTO_SCALARMULT_BYTES = 32;
    const CRYPTO_SCALARMULT_SCALARBYTES = 32;
    const CRYPTO_SHORTHASH_BYTES = 8;
    const CRYPTO_SHORTHASH_KEYBYTES = 16;
    const CRYPTO_SECRETBOX_KEYBYTES = 32;
    const CRYPTO_SECRETBOX_MACBYTES = 16;
    const CRYPTO_SECRETBOX_NONCEBYTES = 24;
    const CRYPTO_SIGN_BYTES = 64;
    const CRYPTO_SIGN_SEEDBYTES = 32;
    const CRYPTO_SIGN_PUBLICKEYBYTES = 32;
    const CRYPTO_SIGN_SECRETKEYBYTES = 64;
    const CRYPTO_SIGN_KEYPAIRBYTES = 96;
    const CRYPTO_STREAM_KEYBYTES = 32;
    const CRYPTO_STREAM_NONCEBYTES = 24;

    /**
     * Cache-timing-safe implementation of bin2hex().
     *
     * @param string $string
     * @return string
     * @throws TypeError
     */
    public static function bin2hex($string)
    {
        if (!is_string($string)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (self::use_fallback('bin2hex')) {
            return call_user_func_array(
                '\\Sodium\\bin2hex',
                array($string)
            );
        }
        return ParagonIE_Sodium_Core_Util::bin2hex($string);
    }

    /**
     * Compare two strings, in constant-time.
     *
     * @param string $left
     * @param string $right
     * @return int
     * @throws TypeError
     */
    public static function compare($left, $right)
    {
        if (!is_string($left)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (!is_string($right)) {
            throw new TypeError('Argument 2 must be a string');
        }
        if (self::use_fallback('compare')) {
            return call_user_func_array(
                '\\Sodium\\compare',
                array($left, $right)
            );
        }
        return ParagonIE_Sodium_Core_Util::compare($left, $right);
    }

    /**
     * Authenticated Encryption with Associated Data: Decryption
     *
     * Algorithm:
     *     ChaCha20-Poly1305
     *
     * @param string $ciphertext
     * @param string $assocData
     * @param string $nonce
     * @param string $key
     *
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_aead_chacha20poly1305_decrypt(
        $ciphertext = '',
        $assocData = '',
        $nonce = '',
        $key = ''
    ) {
        if (!is_string($ciphertext)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (!is_string($assocData)) {
            throw new TypeError('Argument 2 must be a string');
        }
        if (!is_string($nonce)) {
            throw new TypeError('Argument 3 must be a string');
        }
        if (!is_string($key)) {
            throw new TypeError('Argument 4 must be a string');
        }
        if (self::use_fallback('crypto_aead_chacha20poly1305_encrypt')) {
            return call_user_func_array(
                '\\Sodium\\crypto_aead_chacha20poly1305_decrypt',
                array($ciphertext, $assocData, $nonce, $key)
            );
        }
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES) {
            throw new Error('Nonce must be CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES long');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES) {
            throw new Error('Key must be CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES long');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($ciphertext) < self::CRYPTO_AEAD_CHACHA20POLY1305_ABYTES) {
            throw new Error('Message must be at least CRYPTO_AEAD_CHACHA20POLY1305_ABYTES long');
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
     * @param string $plaintext
     * @param string $assocData
     * @param string $nonce
     * @param string $key
     *
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_aead_chacha20poly1305_encrypt(
        $plaintext = '',
        $assocData = '',
        $nonce = '',
        $key = ''
    ) {
        if (!is_string($plaintext)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (!is_string($assocData)) {
            throw new TypeError('Argument 2 must be a string');
        }
        if (!is_string($nonce)) {
            throw new TypeError('Argument 3 must be a string');
        }
        if (!is_string($key)) {
            throw new TypeError('Argument 4 must be a string');
        }
        if (self::use_fallback('crypto_aead_chacha20poly1305_encrypt')) {
            return call_user_func_array(
                '\\Sodium\\crypto_aead_chacha20poly1305_encrypt',
                array($plaintext, $assocData, $nonce, $key)
            );
        }
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES) {
            throw new Error('Nonce must be CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES long');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES) {
            throw new Error('Key must be CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES long');
        }
        return ParagonIE_Sodium_Crypto::aead_chacha20poly1305_encrypt(
            $plaintext,
            $assocData,
            $nonce,
            $key
        );
    }

    /**
     * Authenticate a message. Uses symmetric-key cryptography.
     *
     * Algorithm:
     *     HMAC-SHA512-256. Which is HMAC-SHA-512 truncated to 256 bits.
     *     Not to be confused with HMAC-SHA-512/256 which would use the
     *     SHA-512/256 hash function (uses different initial parameters
     *     but still truncates to 256 bits to sidestep length-extension
     *     attacks.
     *
     * @param string $message
     * @param string $key
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_auth($message, $key)
    {
        if (!is_string($message)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (!is_string($key)) {
            throw new TypeError('Argument 2 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_AUTH_KEYBYTES) {
            throw new Error('Argument 2 must be CRYPTO_AUTH_KEYBYTES long.');
        }
        if (self::use_fallback('crypto_auth')) {
            return call_user_func_array(
                '\\Sodium\\crypto_auth',
                array($message, $key)
            );
        }
        return ParagonIE_Sodium_Crypto::auth($message, $key);
    }

    /**
     * Verify the MAC of a message previously authenticated with crypto_auth.
     *
     * @param string $mac
     * @param string $message
     * @param string $key
     * @return bool
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_auth_verify($mac, $message, $key)
    {
        if (!is_string($message)) {
            throw new TypeError('Argument 2 must be a string');
        }
        if (!is_string($key)) {
            throw new TypeError('Argument 3 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($mac) !== self::CRYPTO_AUTH_BYTES) {
            throw new Error('Argument 1 must be CRYPTO_AUTH_BYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_AUTH_KEYBYTES) {
            throw new Error('Argument 3 must be CRYPTO_AUTH_KEYBYTES long.');
        }
        if (self::use_fallback('crypto_auth_verify')) {
            return call_user_func_array(
                '\\Sodium\\crypto_auth_verify',
                array($mac, $message, $key)
            );
        }
        return ParagonIE_Sodium_Crypto::auth_verify($mac, $message, $key);
    }

    /**
     * Authenticated asymmetric-key encryption. Both the sender and recipient
     * may decrypt messages.
     *
     * Algorithm: X25519-Xsalsa20-Poly1305.
     *     X25519: Elliptic-Curve Diffie Hellman over Curve25519.
     *     Xsalsa20: Extended-nonce variant of salsa20.
     *     Poyl1305: Polynomial MAC for one-time message authentication.
     *
     * @param string $plaintext
     * @param string $nonce
     * @param string $keypair
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_box($plaintext, $nonce, $keypair)
    {
        if (!is_string($plaintext)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (!is_string($nonce)) {
            throw new TypeError('Argument 2 must be a string');
        }
        if (!is_string($keypair)) {
            throw new TypeError('Argument 3 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_BOX_NONCEBYTES) {
            throw new Error('Argument 2 must be CRYPTO_BOX_NONCEBYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($keypair) !== self::CRYPTO_BOX_KEYPAIRBYTES) {
            throw new Error('Argument 3 must be CRYPTO_BOX_KEYPAIRBYTES long.');
        }
        if (self::use_fallback('crypto_box')) {
            return call_user_func_array(
                '\\Sodium\\crypto_box',
                array($plaintext, $nonce, $keypair)
            );
        }
        return ParagonIE_Sodium_Crypto::box($plaintext, $nonce, $keypair);
    }

    /**
     * Anonymous public-key encryption. Only the recipient may decrypt messages.
     *
     * Algorithm: X25519-Xsalsa20-Poly1305, as with crypto_box.
     *     The sender's X25519 keypair is ephemeral.
     *     Nonce is generated from the BLAKE2b hash of both public keys.
     *
     * This provides ciphertext integrity.
     *
     * @param string $plaintext
     * @param string $publicKey
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_box_seal($plaintext, $publicKey)
    {
        if (!is_string($plaintext)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (!is_string($publicKey)) {
            throw new TypeError('Argument 2 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($publicKey) !== self::CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new Error('Argument 2 must be CRYPTO_BOX_PUBLICKEYBYTES long.');
        }
        if (self::use_fallback('crypto_box_seal')) {
            return call_user_func_array(
                '\\Sodium\\crypto_box_seal',
                array($plaintext, $publicKey)
            );
        }
        return ParagonIE_Sodium_Crypto::box_seal($plaintext, $publicKey);
    }

    /**
     * Opens a message encrypted with crypto_box_seal(). Requires
     * the recipient's keypair (sk || pk) to decrypt successfully.
     *
     * This validates ciphertext integrity.
     *
     * @param string $ciphertext
     * @param string $keypair
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_box_seal_open($ciphertext, $keypair)
    {
        if (!is_string($ciphertext)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (!is_string($keypair)) {
            throw new TypeError('Argument 2 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($keypair) !== self::CRYPTO_BOX_KEYPAIRBYTES) {
            throw new Error('Argument 2 must be CRYPTO_BOX_KEYPAIRBYTES long.');
        }
        if (self::use_fallback('crypto_box_seal_open')) {
            return call_user_func_array(
                '\\Sodium\\crypto_box_seal_open',
                array($ciphertext, $keypair)
            );
        }
        return ParagonIE_Sodium_Crypto::box_seal_open($ciphertext, $keypair);
    }

    /**
     * Generate a new random X25519 keypair.
     *
     * @return string
     */
    public static function crypto_box_keypair()
    {
        if (self::use_fallback('crypto_sign_keypair')) {
            return call_user_func(
                '\\Sodium\\crypto_box_keypair'
            );
        }
        return ParagonIE_Sodium_Crypto::box_keypair();
    }

    /**
     * Combine two keys into a keypair for use in library methods that expect
     * a keypair. This doesn't necessarily have to be the same person's keys.
     *
     * @param string $sk Secret key
     * @param string $pk Public key
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_box_keypair_from_secretkey_and_publickey($sk, $pk)
    {
        if (!is_string($sk)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($sk) !== self::CRYPTO_BOX_SECRETKEYBYTES) {
            throw new Error('Argument 1 must be CRYPTO_BOX_SECRETKEYBYTES long.');
        }
        if (!is_string($pk)) {
            throw new TypeError('Argument 2 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($pk) !== self::CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new Error('Argument 2 must be CRYPTO_BOX_PUBLICKEYBYTES long.');
        }
        if (self::use_fallback('box_keypair_from_secretkey_and_publickey')) {
            return call_user_func_array(
                '\\Sodium\\box_keypair_from_secretkey_and_publickey',
                array($sk, $pk)
            );
        }
        return ParagonIE_Sodium_Crypto::box_keypair_from_secretkey_and_publickey($sk, $pk);
    }

    /**
     * Extract the public key from a crypto_box keypair.
     *
     * @param string $keypair
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_box_publickey($keypair)
    {
        if (!is_string($keypair)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($keypair) !== self::CRYPTO_BOX_KEYPAIRBYTES) {
            throw new Error('Argument 1 must be CRYPTO_BOX_KEYPAIRBYTES long.');
        }
        if (self::use_fallback('crypto_box_publickey')) {
            return call_user_func_array(
                '\\Sodium\\crypto_box_publickey',
                array($keypair)
            );
        }
        return ParagonIE_Sodium_Crypto::box_publickey($keypair);
    }

    /**
     * Calculate the X25519 public key from a given X25519 secret key.
     *
     * @param string $sk
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_box_publickey_from_secretkey($sk)
    {
        if (!is_string($sk)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($sk) !== self::CRYPTO_BOX_SECRETKEYBYTES) {
            throw new Error('Argument 1 must be CRYPTO_BOX_SECRETKEYBYTES long.');
        }
        if (self::use_fallback('crypto_box_publickey_from_secretkey')) {
            return call_user_func_array(
                '\\Sodium\\crypto_box_publickey_from_secretkey',
                array($sk)
            );
        }
        return ParagonIE_Sodium_Crypto::box_publickey_from_secretkey($sk);
    }

    /**
     * Extract the secret key from a crypto_box keypair.
     *
     * @param string $keypair
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_box_secretkey($keypair)
    {
        if (!is_string($keypair)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($keypair) !== self::CRYPTO_BOX_KEYPAIRBYTES) {
            throw new Error('Argument 1 must be CRYPTO_BOX_KEYPAIRBYTES long.');
        }
        if (self::use_fallback('crypto_box_secretkey')) {
            return call_user_func_array(
                '\\Sodium\\crypto_box_secretkey',
                array($keypair)
            );
        }
        return ParagonIE_Sodium_Crypto::box_secretkey($keypair);
    }

    /**
     * Decrypt a message previously encrypted with crypto_box().
     *
     * @param string $ciphertext
     * @param string $nonce
     * @param string $keypair
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_box_open($ciphertext, $nonce, $keypair)
    {
        if (!is_string($ciphertext)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (!is_string($nonce)) {
            throw new TypeError('Argument 2 must be a string');
        }
        if (!is_string($keypair)) {
            throw new TypeError('Argument 3 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($ciphertext) < self::CRYPTO_BOX_MACBYTES) {
            throw new Error('Argument 1 must be at least CRYPTO_BOX_MACBYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_BOX_NONCEBYTES) {
            throw new Error('Argument 2 must be CRYPTO_BOX_NONCEBYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($keypair) !== self::CRYPTO_BOX_KEYPAIRBYTES) {
            throw new Error('Argument 3 must be CRYPTO_BOX_KEYPAIRBYTES long.');
        }
        if (self::use_fallback('crypto_box_open')) {
            return call_user_func_array(
                '\\Sodium\\crypto_box_open',
                array($ciphertext, $nonce, $keypair)
            );
        }
        return ParagonIE_Sodium_Crypto::box_open($ciphertext, $nonce, $keypair);
    }

    /**
     * Calculates a BLAKE2b hash, with an optional key.
     *
     * @param string $message
     * @param string $key
     * @param int $length
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_generichash($message, $key = '', $length = 32)
    {
        if (!is_string($message)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (!is_string($key)) {
            throw new TypeError('Argument 2 must be a string');
        }
        if (!is_int($length)) {
            if (is_numeric($length)) {
                $length = (int) $length;
            } else {
                throw new TypeError('Argument 3 must be an integer');
            }
        }
        if (!empty($key)) {
            if (ParagonIE_Sodium_Core_Util::strlen($key) < self::CRYPTO_GENERICHASH_KEYBYTES_MIN) {
                throw new Error('Unsupported key size. Must be at least CRYPTO_GENERICHASH_KEYBYTES_MIN bytes long.');
            }
            if (ParagonIE_Sodium_Core_Util::strlen($key) > self::CRYPTO_GENERICHASH_KEYBYTES_MAX) {
                throw new Error('Unsupported key size. Must be at most CRYPTO_GENERICHASH_KEYBYTES_MAX bytes long.');
            }
        }
        if (self::use_fallback('crypto_generichash')) {
            return call_user_func_array(
                '\\Sodium\\crypto_generichash',
                array($message, $key, $length)
            );
        }
        return ParagonIE_Sodium_Crypto::generichash($message, $key, $length);
    }

    /**
     * Get the final BLAKE2b hash output for a given context.
     *
     * @param string &$ctx
     * @param int $length
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_generichash_final(&$ctx, $length = 32)
    {
        if (!is_string($ctx)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (!is_int($length)) {
            if (is_numeric($length)) {
                $length = (int) $length;
            } else {
                throw new TypeError('Argument 2 must be an integer');
            }
        }
        if (self::use_fallback('crypto_generichash_final')) {
            $func = '\\Sodium\\crypto_generichash_final';
            return $func($ctx, $length);
        }
        $result = ParagonIE_Sodium_Crypto::generichash_final($ctx, $length);
        try {
            self::memzero($ctx);
        } catch (Error $ex) {
            $ctx = null;
        }
        return $result;
    }

    /**
     * Initialize a BLAKE2b hashing context, for use in a streaming interface.
     *
     * @param string $key
     * @param int $length
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_generichash_init($key = '', $length = 32)
    {
        if (!is_string($key)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (!is_int($length)) {
            if (is_numeric($length)) {
                $length = (int) $length;
            } else {
                throw new TypeError('Argument 2 must be an integer');
            }
        }
        if (!empty($key)) {
            if (ParagonIE_Sodium_Core_Util::strlen($key) < self::CRYPTO_GENERICHASH_KEYBYTES_MIN) {
                throw new Error('Unsupported key size. Must be at least CRYPTO_GENERICHASH_KEYBYTES_MIN bytes long.');
            }
            if (ParagonIE_Sodium_Core_Util::strlen($key) > self::CRYPTO_GENERICHASH_KEYBYTES_MAX) {
                throw new Error('Unsupported key size. Must be at most CRYPTO_GENERICHASH_KEYBYTES_MAX bytes long.');
            }
        }
        if (self::use_fallback('crypto_generichash_init')) {
            return call_user_func_array(
                '\\Sodium\\crypto_generichash_init',
                array($key, $length)
            );
        }
        return ParagonIE_Sodium_Crypto::generichash_init($key, $length);
    }

    /**
     * Update a BLAKE2b hashing context with additional data.
     *
     * @param string &$ctx
     * @param string $message
     * @return void
     * @throws TypeError
     */
    public static function crypto_generichash_update(&$ctx, $message)
    {
        if (!is_string($ctx)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (!is_string($message)) {
            throw new TypeError('Argument 2 must be a string');
        }
        if (self::use_fallback('crypto_generichash_update')) {
            $func = '\\Sodium\\crypto_generichash_update';
            $func($ctx, $message);
            return;
        }
        $ctx = ParagonIE_Sodium_Crypto::generichash_update($ctx, $message);
    }

    /**
     * Perform a key exchange, between a designated client and a server.
     *
     * @param string $my_secret
     * @param string $their_public
     * @param string $client_public
     * @param string $server_public
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_kx($my_secret, $their_public, $client_public, $server_public)
    {
        if (!is_string($my_secret)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($my_secret) !== self::CRYPTO_BOX_SECRETKEYBYTES) {
            throw new Error('Argument 1 must be CRYPTO_BOX_SECRETKEYBYTES long.');
        }
        if (!is_string($their_public)) {
            throw new TypeError('Argument 2 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($their_public) !== self::CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new Error('Argument 2 must be CRYPTO_BOX_PUBLICKEYBYTES long.');
        }
        if (!is_string($client_public)) {
            throw new TypeError('Argument 3 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($client_public) !== self::CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new Error('Argument 3 must be CRYPTO_BOX_PUBLICKEYBYTES long.');
        }
        if (!is_string($server_public)) {
            throw new TypeError('Argument 4 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($server_public) !== self::CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new Error('Argument 4 must be CRYPTO_BOX_PUBLICKEYBYTES long.');
        }
        if (self::use_fallback('crypto_kx')) {
            return call_user_func_array(
                '\\Sodium\\crypto_kx',
                func_get_args()
            );
        }
        return ParagonIE_Sodium_Crypto::kx(
            $my_secret,
            $their_public,
            $client_public,
            $server_public
        );
    }

    /**
     * Calculate the shared secret between your secret key and your
     * recipient's public key.
     *
     * Algorithm: X25519 (ECDH over Curve25519)
     *
     * @param string $sk
     * @param string $pk
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_scalarmult($sk, $pk)
    {
        if (!is_string($sk)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($sk) !== self::CRYPTO_BOX_SECRETKEYBYTES) {
            throw new Error('Argument 1 must be CRYPTO_BOX_SECRETKEYBYTES long.');
        }
        if (!is_string($pk)) {
            throw new TypeError('Argument 2 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($pk) !== self::CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new Error('Argument 2 must be CRYPTO_BOX_PUBLICKEYBYTES long.');
        }
        if (self::use_fallback('crypto_scalarmult')) {
            return call_user_func_array(
                '\\Sodium\\crypto_scalarmult',
                array($sk, $pk)
            );
        }
        return ParagonIE_Sodium_Crypto::scalarmult($sk, $pk);
    }

    /**
     * Calculate an X25519 public key from an X25519 secret key.
     *
     * @param string $sk
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_scalarmult_base($sk)
    {
        if (!is_string($sk)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($sk) !== self::CRYPTO_BOX_SECRETKEYBYTES) {
            throw new Error('Argument 1 must be CRYPTO_BOX_SECRETKEYBYTES long.');
        }
        if (self::use_fallback('crypto_scalarmult_base')) {
            return call_user_func_array(
                '\\Sodium\\crypto_scalarmult_base',
                array($sk)
            );
        }
        return ParagonIE_Sodium_Crypto::scalarmult_base($sk);
    }

    /**
     * Authenticated symmetric-key encryption.
     *
     * Algorithm: Xsalsa20-Poly1305
     *
     * @param string $plaintext
     * @param string $nonce
     * @param string $key
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_secretbox($plaintext, $nonce, $key)
    {
        if (!is_string($plaintext)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (!is_string($nonce)) {
            throw new TypeError('Argument 2 must be a string');
        }
        if (!is_string($key)) {
            throw new TypeError('Argument 3 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_SECRETBOX_NONCEBYTES) {
            throw new Error('Argument 2 must be CRYPTO_SECRETBOX_NONCEBYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_SECRETBOX_KEYBYTES) {
            throw new Error('Argument 3 must be CRYPTO_SECRETBOX_KEYBYTES long.');
        }
        if (self::use_fallback('crypto_secretbox')) {
            return call_user_func_array(
                '\\Sodium\\crypto_secretbox',
                array($plaintext, $nonce, $key)
            );
        }
        return ParagonIE_Sodium_Crypto::secretbox($plaintext, $nonce, $key);
    }

    /**
     * Decrypts a message previously encrypted with crypto_secretbox().
     *
     * @param string $ciphertext
     * @param string $nonce
     * @param string $key
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_secretbox_open($ciphertext, $nonce, $key)
    {
        if (!is_string($ciphertext)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (!is_string($nonce)) {
            throw new TypeError('Argument 2 must be a string');
        }
        if (!is_string($key)) {
            throw new TypeError('Argument 3 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_SECRETBOX_NONCEBYTES) {
            throw new Error('Argument 2 must be CRYPTO_SECRETBOX_NONCEBYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_SECRETBOX_KEYBYTES) {
            throw new Error('Argument 3 must be CRYPTO_SECRETBOX_KEYBYTES long.');
        }
        if (self::use_fallback('crypto_secretbox_open')) {
            return call_user_func_array(
                '\\Sodium\\crypto_secretbox_open',
                array($ciphertext, $nonce, $key)
            );
        }
        return ParagonIE_Sodium_Crypto::secretbox_open($ciphertext, $nonce, $key);
    }

    /**
     * Calculates a SipHash-2-4 hash of a message for a given key.
     *
     * @param string $message
     * @param string $key
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_shorthash($message, $key)
    {
        if (!is_string($message)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (!is_string($key)) {
            throw new TypeError('Argument 2 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_SHORTHASH_KEYBYTES) {
            throw new Error('Argument 2 must be CRYPTO_SHORTHASH_KEYBYTES long.');
        }
        if (self::use_fallback('crypto_shorthash')) {
            return call_user_func_array(
                '\\Sodium\\crypto_shorthash',
                array($message, $key)
            );
        }
        return ParagonIE_Sodium_Core_SipHash::sipHash24($message, $key);
    }

    /**
     * Expand a key and nonce into a keystream of pseudorandom bytes.
     *
     * @param int $len
     * @param string $nonce
     * @param string $key
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_stream($len, $nonce, $key)
    {
        if (!is_int($len)) {
            if (is_numeric($len)) {
                $len = (int) $len;
            } else {
                throw new TypeError('Argument 1 must be an integer');
            }
        }
        if (!is_string($nonce)) {
            throw new TypeError('Argument 2 must be a string');
        }
        if (!is_string($key)) {
            throw new TypeError('Argument 3 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_STREAM_NONCEBYTES) {
            throw new Error('Argument 2 must be CRYPTO_SECRETBOX_NONCEBYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_STREAM_KEYBYTES) {
            throw new Error('Argument 3 must be CRYPTO_STREAM_KEYBYTES long.');
        }
        if (self::use_fallback('crypto_stream')) {
            return call_user_func_array(
                '\\Sodium\\crypto_stream',
                array($len, $nonce, $key)
            );
        }
        return ParagonIE_Sodium_Core_Xsalsa20::xsalsa20($len, $nonce, $key);
    }

    /**
     * DANGER! UNAUTHENTICATED ENCRYPTION!
     *
     * Unless you are following expert advice, do not used this feature.
     *
     * Algorithm: Xsalsa20
     *
     * This DOES NOT provide ciphertext integrity.
     *
     * @param string $message
     * @param string $nonce
     * @param string $key
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_stream_xor($message, $nonce, $key)
    {
        if (!is_string($message)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (!is_string($nonce)) {
            throw new TypeError('Argument 2 must be a string');
        }
        if (!is_string($key)) {
            throw new TypeError('Argument 3 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($nonce) !== self::CRYPTO_STREAM_NONCEBYTES) {
            throw new Error('Argument 2 must be CRYPTO_SECRETBOX_NONCEBYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($key) !== self::CRYPTO_STREAM_KEYBYTES) {
            throw new Error('Argument 3 must be CRYPTO_SECRETBOX_KEYBYTES long.');
        }
        if (self::use_fallback('crypto_stream_xor')) {
            return call_user_func_array(
                '\\Sodium\\crypto_stream_xor',
                array($message, $nonce, $key)
            );
        }
        return ParagonIE_Sodium_Core_Xsalsa20::xsalsa20_xor($message, $nonce, $key);
    }

    /**
     * Returns a signed message. You probably want crypto_sign_detached()
     * instead, which only returns the signature.
     *
     * Algorithm: Ed25519 (EdDSA over Curve25519)
     *
     * @param string $message
     * @param string $sk
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_sign($message, $sk)
    {
        if (!is_string($message)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (!is_string($sk)) {
            throw new TypeError('Argument 2 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($sk) !== self::CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new Error('Argument 2 must be CRYPTO_SIGN_SECRETKEYBYTES long.');
        }
        if (self::use_fallback('crypto_sign')) {
            return call_user_func_array(
                '\\Sodium\\crypto_sign',
                array($message, $sk)
            );
        }
        return ParagonIE_Sodium_Crypto::sign($message, $sk);
    }

    /**
     * Validates a signed message then returns the message.
     *
     * @param string $sm
     * @param string $pk
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_sign_open($sm, $pk)
    {
        if (!is_string($sm)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (!is_string($pk)) {
            throw new TypeError('Argument 2 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($pk) !== self::CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new Error('Argument 2 must be CRYPTO_SIGN_PUBLICKEYBYTES long.');
        }
        if (self::use_fallback('crypto_sign_open')) {
            return call_user_func_array(
                '\\Sodium\\crypto_sign_open',
                array($sm, $pk)
            );
        }
        return ParagonIE_Sodium_Crypto::sign_open($sm, $pk);
    }

    /**
     * Generate a new random Ed25519 keypair.
     *
     * @return string
     */
    public static function crypto_sign_keypair()
    {
        if (self::use_fallback('crypto_sign_keypair')) {
            return call_user_func(
                '\\Sodium\\crypto_sign_keypair'
            );
        }
        return ParagonIE_Sodium_Core_Ed25519::keypair();
    }

    /**
     * Generate an Ed25519 keypair from a seed.
     *
     * @param string $seed
     * @return string
     */
    public static function crypto_sign_seed_keypair($seed)
    {
        if (self::use_fallback('crypto_sign_keypair')) {
            return call_user_func_array(
                '\\Sodium\\crypto_sign_seed_keypair',
                array($seed)
            );
        }
        $pk = '';
        $sk = '';
        ParagonIE_Sodium_Core_Ed25519::seed_keypair($pk, $sk, $seed);
        return $sk . $pk;
    }

    /**
     * Extract an Ed25519 public key from an Ed25519 keypair.
     *
     * @param string $keypair
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_sign_publickey($keypair)
    {
        if (!is_string($keypair)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($keypair) !== self::CRYPTO_SIGN_KEYPAIRBYTES) {
            throw new Error('Argument 1 must be CRYPTO_SIGN_KEYPAIRBYTES long.');
        }
        if (self::use_fallback('crypto_sign_publickey')) {
            return call_user_func_array(
                '\\Sodium\\crypto_sign_publickey',
                array($keypair)
            );
        }
        return ParagonIE_Sodium_Core_Ed25519::publickey($keypair);
    }
    /**
     * Calculate an Ed25519 public key from an Ed25519 secret key.
     *
     * @param string $sk
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_sign_publickey_from_secretkey($sk)
    {
        if (!is_string($sk)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($sk) !== self::CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new Error('Argument 1 must be CRYPTO_SIGN_SECRETKEYBYTES long.');
        }
        if (self::use_fallback('crypto_sign_publickey_from_publickey')) {
            return call_user_func_array(
                '\\Sodium\\crypto_sign_publickey_from_publickey',
                array($sk)
            );
        }
        return ParagonIE_Sodium_Core_Ed25519::publickey_from_secretkey($sk);
    }

    /**
     * Extract an Ed25519 secret key from an Ed25519 keypair.
     *
     * @param string $keypair
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_sign_secretkey($keypair)
    {
        if (!is_string($keypair)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($keypair) !== self::CRYPTO_SIGN_KEYPAIRBYTES) {
            throw new Error('Argument 1 must be CRYPTO_SIGN_KEYPAIRBYTES long.');
        }
        if (self::use_fallback('crypto_sign_secretkey')) {
            return call_user_func_array(
                '\\Sodium\\crypto_sign_secretkey',
                array($keypair)
            );
        }
        return ParagonIE_Sodium_Core_Ed25519::secretkey($keypair);
    }

    /**
     * Calculate the Ed25519 signature of a message and return ONLY the signature.
     *
     * Algorithm: Ed25519 (EdDSA over Curve25519)
     *
     * @param string $message
     * @param string $sk
     * @return string
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_sign_detached($message, $sk)
    {
        if (!is_string($message)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (!is_string($sk)) {
            throw new TypeError('Argument 2 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($sk) !== self::CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new Error('Argument 2 must be CRYPTO_SIGN_SECRETKEYBYTES long.');
        }
        if (self::use_fallback('crypto_sign_detached')) {
            return call_user_func_array(
                '\\Sodium\\crypto_sign_detached',
                array($message, $sk)
            );
        }
        return ParagonIE_Sodium_Crypto::sign_detached($message, $sk);
    }

    /**
     * Verify the signature of a message.
     *
     * @param string $signature
     * @param string $message
     * @param string $pk
     * @return bool
     * @throws Error
     * @throws TypeError
     */
    public static function crypto_sign_verify_detached($signature, $message, $pk)
    {
        if (!is_string($signature)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (!is_string($message)) {
            throw new TypeError('Argument 2 must be a string');
        }
        if (!is_string($pk)) {
            throw new TypeError('Argument 3 must be a string');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($signature) !== self::CRYPTO_SIGN_BYTES) {
            throw new Error('Argument 1 must be CRYPTO_SIGN_BYTES long.');
        }
        if (ParagonIE_Sodium_Core_Util::strlen($pk) !== self::CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new Error('Argument 3 must be CRYPTO_SIGN_PUBLICKEYBYTES long.');
        }
        if (self::use_fallback('crypto_sign_verify_detached')) {
            return call_user_func_array(
                '\\Sodium\\crypto_sign_verify_detached',
                array($signature, $message, $pk)
            );
        }
        return ParagonIE_Sodium_Crypto::sign_verify_detached($signature, $message, $pk);
    }

    /**
     * Cache-timing-safe implementation of hex2bin().
     *
     * @param string $string
     * @return string
     * @throws TypeError
     */
    public static function hex2bin($string)
    {
        if (!is_string($string)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (self::use_fallback('hex2bin')) {
            return call_user_func_array(
                '\\Sodium\\hex2bin',
                array($string)
            );
        }
        return ParagonIE_Sodium_Core_Util::hex2bin($string);
    }

    /**
     * @return int
     */
    public static function library_version_major()
    {
        if (self::use_fallback('hex2bin')) {
            return (int) call_user_func('\\Sodium\\library_version_minor');
        }
        return self::LIBRARY_VERSION_MAJOR;
    }

    /**
     * @return int
     */
    public static function library_version_minor()
    {
        if (self::use_fallback('library_version_minor')) {
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
     * @throws TypeError
     */
    public static function memcmp($left, $right)
    {
        if (!is_string($left)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (!is_string($right)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (self::use_fallback('memcmp')) {
            return call_user_func_array(
                '\\Sodium\\memcmp',
                array($left, $right)
            );
        }
        return ParagonIE_Sodium_Core_Util::memcmp($left, $right);
    }

    /**
     * This is a NOP in the userland implementation. It's actually not possible
     * to zero memory buffers in PHP. You need the native library for that.
     *
     * @param &string $var
     * @return void
     * @throws Error
     * @throws TypeError
     */
    public static function memzero(&$var)
    {
        if (!is_string($var)) {
            throw new TypeError('Argument 1 must be a string');
        }
        if (self::use_fallback('memzero')) {
            call_user_func_array(
                '\\Sodium\\memzero',
                array(&$var)
            );
            return;
        }
        // This is the best we can do.
        throw new Error(
            'This is not implemented, as it is not possible to securely wipe memory from PHP'
        );
    }

    /**
     * Generate a string of bytes from the kernel's CSPRNG.
     * Proudly uses /dev/urandom (if getrandom(2) is not available).
     *
     * @param int $numBytes
     * @return string
     * @throws TypeError
     */
    public static function randombytes_buf($numBytes)
    {
        if (!is_int($numBytes)) {
            if (is_numeric($numBytes)) {
                $numBytes = (int) $numBytes;
            } else {
                throw new TypeError('Argument 1 must be an integer');
            }
        }
        if (self::use_fallback('randombytes_buf')) {
            return call_user_func_array(
                '\\Sodium\\randombytes_buf',
                array($numBytes)
            );
        }
        return random_bytes($numBytes);
    }

    /**
     * Generate an integer between 0 and $range (non-inclusive).
     *
     * @param int $range
     * @return int
     * @throws TypeError
     */
    public static function randombytes_uniform($range)
    {
        if (!is_int($range)) {
            if (is_numeric($range)) {
                $range = (int) $range;
            } else {
                throw new TypeError('Argument 1 must be an integer');
            }
        }
        if (self::use_fallback('randombytes_uniform')) {
            return (int) call_user_func_array(
                '\\Sodium\\randombytes_uniform',
                array($range)
            );
        }
        return random_int(0, $range - 1);
    }

    /**
     * Generate a random 16-bit integer.
     *
     * @return int
     */
    public static function randombytes_random16()
    {
        if (self::use_fallback('randombytes_random16')) {
            return (int) call_user_func('\\Sodium\\randombytes_random16');
        }
        return random_int(0, 65535);
    }

    /**
     * @return string
     */
    public static function version_string()
    {
        if (self::use_fallback('version_string')) {
            return (string) call_user_func('\\Sodium\\version_string');
        }
        return self::VERSION_STRING;
    }

    /**
     * Should we use the libsodium core function instead?
     *
     * @param string $sodium_func_name
     * @return bool
     */
    protected static function use_fallback($sodium_func_name = '')
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
}
