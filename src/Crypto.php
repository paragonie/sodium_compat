<?php

/**
 * Class ParagonIE_Sodium_Crypto
 *
 * ATTENTION!
 *
 * If you are using this library, you should be using
 * ParagonIE_Sodium_Compat in your code, not this class.
 */
abstract class ParagonIE_Sodium_Crypto
{
    const aead_chacha20poly1305_KEYBYTES = 32;
    const aead_chacha20poly1305_NSECBYTES = 0;
    const aead_chacha20poly1305_NPUBBYTES = 8;
    const aead_chacha20poly1305_ABYTES = 16;
    const aead_chacha20poly1305_IETF_KEYBYTES = 32;
    const aead_chacha20poly1305_IETF_NSECBYTES = 0;
    const aead_chacha20poly1305_IETF_NPUBBYTES = 12;
    const aead_chacha20poly1305_IETF_ABYTES = 16;
    const box_curve25519xsalsa20poly1305_SEEDBYTES = 32;
    const box_curve25519xsalsa20poly1305_PUBLICKEYBYTES = 32;
    const box_curve25519xsalsa20poly1305_SECRETKEYBYTES = 32;
    const box_curve25519xsalsa20poly1305_BEFORENMBYTES = 32;
    const box_curve25519xsalsa20poly1305_NONCEBYTES = 24;
    const box_curve25519xsalsa20poly1305_MACBYTES = 16;
    const box_curve25519xsalsa20poly1305_BOXZEROBYTES = 16;
    const box_curve25519xsalsa20poly1305_ZEROBYTES = 32;

    const onetimeauth_poly1305_BYTES = 16;
    const onetimeauth_poly1305_KEYBYTES = 32;

    const secretbox_xsalsa20poly1305_KEYBYTES = 32;
    const secretbox_xsalsa20poly1305_NONCEBYTES = 24;
    const secretbox_xsalsa20poly1305_MACBYTES = 16;
    const secretbox_xsalsa20poly1305_BOXZEROBYTES = 16;
    const secretbox_xsalsa20poly1305_ZEROBYTES = 32;

    const stream_salsa20_KEYBYTES = 32;

    /**
     * AEAD Decryption with ChaCha20-Poly1305
     *
     * @param string $message
     * @param string $ad
     * @param string $nonce
     * @param string $key
     * @return string
     * @throws Exception
     */
    public static function aead_chacha20poly1305_decrypt(
        $message = '',
        $ad = '',
        $nonce = '',
        $key = ''
    ) {
        $block0 = ParagonIE_Sodium_Core_ChaCha20::stream(
            32,
            $nonce,
            $key
        );

        $state = new ParagonIE_Sodium_Core_Poly1305_State($block0);
        try {
            ParagonIE_Sodium_Compat::memzero($block0);
        } catch (Error $ex) {
            $block0 = null;
        }

        $state->update($ad);
        $state->update(
            ParagonIE_Sodium_Core_Util::store64_le(
                ParagonIE_Sodium_Core_Util::strlen($ad)
            )
        );

        $len = ParagonIE_Sodium_Core_Util::strlen($message);
        $mac = ParagonIE_Sodium_Core_Util::substr(
            $message,
            $len - self::aead_chacha20poly1305_ABYTES,
            self::aead_chacha20poly1305_ABYTES
        );
        $ciphertext = ParagonIE_Sodium_Core_Util::substr(
            $message,
            0,
            $len - self::aead_chacha20poly1305_ABYTES
        );

        $state->update($ciphertext);
        $state->update(
            ParagonIE_Sodium_Core_Util::store64_le($len - 16)
        );

        $computed_mac = $state->finish();

        if (!ParagonIE_Sodium_Core_Util::verify_16($computed_mac, $mac)) {
            throw new Exception('Invalid MAC');
        }
        return ParagonIE_Sodium_Core_ChaCha20::streamXorIc(
            $ciphertext,
            $nonce,
            $key,
            ParagonIE_Sodium_Core_Util::store64_le(1)
        );
    }

    /**
     * AEAD Encryption with ChaCha20-Poly1305
     *
     * @param string $message
     * @param string $ad
     * @param string $nonce
     * @param string $key
     * @return string
     */
    public static function aead_chacha20poly1305_encrypt(
        $message = '',
        $ad = '',
        $nonce = '',
        $key = ''
    ) {
        # crypto_stream_chacha20(block0, sizeof block0, npub, k);
        $block0 = ParagonIE_Sodium_Core_ChaCha20::stream(
            32,
            $nonce,
            $key
        );
        $state = new ParagonIE_Sodium_Core_Poly1305_State($block0);
        try {
            ParagonIE_Sodium_Compat::memzero($block0);
        } catch (Error $ex) {
            $block0 = null;
        }

        $state->update($ad);
        $state->update(
            ParagonIE_Sodium_Core_Util::store64_le(
                ParagonIE_Sodium_Core_Util::strlen($ad)
            )
        );
        $len = ParagonIE_Sodium_Core_Util::strlen($message);

        $ciphertext = ParagonIE_Sodium_Core_ChaCha20::streamXorIc(
            $message,
            $nonce,
            $key,
            ParagonIE_Sodium_Core_Util::store64_le(1)
        );
        $state->update($ciphertext);
        $state->update(
            ParagonIE_Sodium_Core_Util::store64_le($len)
        );
        return $ciphertext . $state->finish();
    }

    /**
     * AEAD Decryption with ChaCha20-Poly1305, IETF mode (96-bit nonce)
     *
     * @param string $message
     * @param string $ad
     * @param string $nonce
     * @param string $key
     * @return string
     * @throws Exception
     */
    public static function aead_chacha20poly1305_ietf_decrypt(
        $message = '',
        $ad = '',
        $nonce = '',
        $key = ''
    ) {
        $adlen = ParagonIE_Sodium_Core_Util::strlen($ad);
        $len = ParagonIE_Sodium_Core_Util::strlen($message);
        $clen = $len - self::aead_chacha20poly1305_ABYTES;

        $block0 = ParagonIE_Sodium_Core_ChaCha20::ietfStream(
            32,
            $nonce,
            $key
        );

        $mac = ParagonIE_Sodium_Core_Util::substr(
            $message,
            $len - self::aead_chacha20poly1305_ABYTES,
            self::aead_chacha20poly1305_ABYTES
        );
        $ciphertext = ParagonIE_Sodium_Core_Util::substr(
            $message,
            0,
            $len - self::aead_chacha20poly1305_ABYTES
        );

        $state = new ParagonIE_Sodium_Core_Poly1305_State($block0);
        try {
            ParagonIE_Sodium_Compat::memzero($block0);
        } catch (Error $ex) {
            $block0 = null;
        }

        $state->update($ad);
        $state->update(str_repeat("\x00", ((0x10 - $adlen) & 0xf)));
        $state->update($ciphertext);
        $state->update(str_repeat("\x00", (0x10 - $clen) & 0xf));
        $state->update(ParagonIE_Sodium_Core_Util::store64_le($adlen));
        $state->update(ParagonIE_Sodium_Core_Util::store64_le($clen));
        $computed_mac = $state->finish();

        if (!ParagonIE_Sodium_Core_Util::verify_16($computed_mac, $mac)) {
            throw new Exception('Invalid MAC');
        }
        return ParagonIE_Sodium_Core_ChaCha20::ietfStreamXorIc(
            $ciphertext,
            $nonce,
            $key,
            ParagonIE_Sodium_Core_Util::store64_le(1)
        );
    }

    /**
     * AEAD Encryption with ChaCha20-Poly1305, IETF mode (96-bit nonce)
     *
     * @param string $message
     * @param string $ad
     * @param string $nonce
     * @param string $key
     * @return string
     */
    public static function aead_chacha20poly1305_ietf_encrypt(
        $message = '',
        $ad = '',
        $nonce = '',
        $key = ''
    ) {
        $len = ParagonIE_Sodium_Core_Util::strlen($message);
        $adlen = ParagonIE_Sodium_Core_Util::strlen($ad);

        $block0 = ParagonIE_Sodium_Core_ChaCha20::ietfStream(
            32,
            $nonce,
            $key
        );
        $state = new ParagonIE_Sodium_Core_Poly1305_State($block0);
        try {
            ParagonIE_Sodium_Compat::memzero($block0);
        } catch (Error $ex) {
            $block0 = null;
        }

        $state->update($ad);
        $state->update(str_repeat("\x00", ((0x10 - $adlen) & 0xf)));

        $ciphertext = ParagonIE_Sodium_Core_ChaCha20::ietfStreamXorIc(
            $message,
            $nonce,
            $key,
            ParagonIE_Sodium_Core_Util::store64_le(1)
        );
        $state->update($ciphertext);
        $state->update(str_repeat("\x00", ((0x10 - $len) & 0xf)));

        $state->update(
            ParagonIE_Sodium_Core_Util::store64_le($adlen)
        );
        $state->update(
            ParagonIE_Sodium_Core_Util::store64_le($len)
        );
        return $ciphertext . $state->finish();
    }

    /**
     * HMAC-SHA-512-256 (a.k.a. the leftmost 256 bits of HMAC-SHA-512)
     *
     * @param string $message
     * @param string $key
     * @return string
     */
    public static function auth($message, $key)
    {
        return ParagonIE_Sodium_Core_Util::substr(
            hash_hmac('sha512', $message, $key, true),
            0,
            32
        );
    }

    /**
     * HMAC-SHA-512-256 validation. Constant-time via hash_equals().
     *
     * @param string $mac
     * @param string $message
     * @param string $key
     * @return bool
     */
    public static function auth_verify($mac, $message, $key)
    {
        return hash_equals(
            $mac,
            self::auth($message, $key)
        );
    }

    /**
     * X25519 key exchange followed by Xsalsa20Poly1305 symmetric encryption
     *
     * @param string $plaintext
     * @param string $nonce
     * @param string $keypair
     * @return string
     */
    public static function box($plaintext, $nonce, $keypair)
    {
        $c = self::secretbox(
            $plaintext,
            $nonce,
            self::box_beforenm(
                self::box_secretkey($keypair),
                self::box_publickey($keypair)
            )
        );
        return $c;
    }

    /**
     * X25519-Xsalsa20-Poly1305 with one ephemeral X25519 keypair.
     *
     * @param string $message
     * @param string $publicKey
     * @return string
     */
    public static function box_seal($message, $publicKey)
    {
        $ephemeralKeypair = self::box_keypair();
        $ephemeralSK = self::box_secretkey($ephemeralKeypair);
        $ephemeralPK = self::box_publickey($ephemeralKeypair);

        $nonce = self::generichash(
            $ephemeralPK . $publicKey,
            '',
            24
        );
        $keypair = self::box_keypair_from_secretkey_and_publickey($ephemeralSK, $publicKey);

        $ciphertext = self::box($message, $nonce, $keypair);
        try {
            ParagonIE_Sodium_Compat::memzero($ephemeralKeypair);
            ParagonIE_Sodium_Compat::memzero($ephemeralSK);
            ParagonIE_Sodium_Compat::memzero($nonce);
        } catch (Error $ex) {
            $ephemeralKeypair = null;
            $ephemeralSK = null;
            $nonce = null;
        }
        return $ephemeralPK . $ciphertext;
    }

    /**
     * Opens a message encrypted via box_seal().
     *
     * @param string $message
     * @param string $keypair
     * @return string
     */
    public static function box_seal_open($message, $keypair)
    {
        $ephemeralPK = ParagonIE_Sodium_Core_Util::substr($message, 0, 32);
        $ciphertext = ParagonIE_Sodium_Core_Util::substr($message, 32);

        $secretKey = self::box_secretkey($keypair);
        $publicKey = self::box_publickey($keypair);

        $nonce = self::generichash(
            $ephemeralPK . $publicKey,
            '',
            24
        );
        $keypair = self::box_keypair_from_secretkey_and_publickey($secretKey, $ephemeralPK);
        $m = self::box_open($ciphertext, $nonce, $keypair);
        try {
            ParagonIE_Sodium_Compat::memzero($secretKey);
            ParagonIE_Sodium_Compat::memzero($ephemeralPK);
            ParagonIE_Sodium_Compat::memzero($nonce);
        } catch (Error $ex) {
            $secretKey = null;
            $ephemeralPK = null;
            $nonce = null;
        }
        return $m;
    }

    /**
     * Used by crypto_box() to get the crypto_secretbox() key.
     *
     * @param string $sk
     * @param string $pk
     * @return string
     */
    public static function box_beforenm($sk, $pk)
    {
        return ParagonIE_Sodium_Core_HSalsa20::hsalsa20(
            str_repeat("\x00", 16),
            self::scalarmult($sk, $pk)
        );
    }

    /**
     * @return string
     */
    public static function box_keypair()
    {
        $sKey = random_bytes(32);
        $pKey = self::scalarmult_base($sKey);
        return $sKey . $pKey;
    }

    /**
     * @param string $sKey
     * @param string $pKey
     * @return string
     */
    public static function box_keypair_from_secretkey_and_publickey($sKey, $pKey)
    {
        return ParagonIE_Sodium_Core_Util::substr($sKey, 0, 32) .
            ParagonIE_Sodium_Core_Util::substr($pKey, 0, 32);
    }

    /**
     * @param string $keypair
     * @return string
     */
    public static function box_secretkey($keypair)
    {
        if (ParagonIE_Sodium_Core_Util::strlen($keypair) !== 64) {
            throw new RangeException('Must be ParagonIE_Sodium_Compat::CRYPTO_BOX_KEYPAIRBYTES bytes long.');
        }
        return ParagonIE_Sodium_Core_Util::substr($keypair, 0, 32);
    }

    /**
     * @param string $keypair
     * @return string
     * @throws RangeException
     */
    public static function box_publickey($keypair)
    {
        if (ParagonIE_Sodium_Core_Util::strlen($keypair) !== ParagonIE_Sodium_Compat::CRYPTO_BOX_KEYPAIRBYTES) {
            throw new RangeException('Must be ParagonIE_Sodium_Compat::CRYPTO_BOX_KEYPAIRBYTES bytes long.');
        }
        return ParagonIE_Sodium_Core_Util::substr($keypair, 32, 32);
    }

    /**
     * @param string $sKey
     * @return string
     * @throws RangeException
     */
    public static function box_publickey_from_secretkey($sKey)
    {
        if (ParagonIE_Sodium_Core_Util::strlen($sKey) !== ParagonIE_Sodium_Compat::CRYPTO_BOX_SECRETKEYBYTES) {
            throw new RangeException('Must be ParagonIE_Sodium_Compat::CRYPTO_BOX_SECRETKEYBYTES bytes long.');
        }
        return self::scalarmult_base($sKey);
    }

    /**
     * Decrypt a message encrypted with box().
     *
     * @param string $ciphertext
     * @param string $nonce
     * @param string $nonce
     * @param string $keypair
     * @return string
     */
    public static function box_open($ciphertext, $nonce, $keypair)
    {
        return self::secretbox_open(
            $ciphertext,
            $nonce,
            self::box_beforenm(
                self::box_secretkey($keypair),
                self::box_publickey($keypair)
            )
        );
    }

    /**
     * Calculate a BLAKE2b hash.
     *
     * @param string $message
     * @param string|null $key
     * @param int $outlen
     * @return string
     * @throws Exception
     */
    public static function generichash($message, $key = '', $outlen = 32)
    {
        ParagonIE_Sodium_Core_BLAKE2b::pseudoConstructor();

        $k = null;
        if (!empty($key)) {
            $k = ParagonIE_Sodium_Core_BLAKE2b::stringToSplFixedArray($key);
            if ($k->count() > ParagonIE_Sodium_Core_BLAKE2b::KEYBYTES) {
                throw new Exception('Invalid key size');
            }
        }

        $in = ParagonIE_Sodium_Core_BLAKE2b::stringToSplFixedArray($message);
        $ctx = ParagonIE_Sodium_Core_BLAKE2b::init($k, $outlen);
        ParagonIE_Sodium_Core_BLAKE2b::update($ctx, $in, $in->count());
        $out = new SplFixedArray($outlen);
        $out = ParagonIE_Sodium_Core_BLAKE2b::finish($ctx, $out);
        /**
         * @var array<int, int>
         */
        $outArray = $out->toArray();
        return ParagonIE_Sodium_Core_Util::intArrayToString($outArray);
    }

    /**
     * Finalize a BLAKE2b hashing context, returning the hash.
     *
     * @param string $ctx
     * @param int $outlen
     * @return string
     */
    public static function generichash_final($ctx, $outlen = 32)
    {
        if (!is_string($ctx)) {
            throw new InvalidArgumentException('Context must be a string');
        }
        $out = new SplFixedArray($outlen);
        $context = ParagonIE_Sodium_Core_BLAKE2b::stringToContext($ctx);
        $out = ParagonIE_Sodium_Core_BLAKE2b::finish($context, $out);
        /**
         * @var array<int, int>
         */
        $outArray = $out->toArray();
        return ParagonIE_Sodium_Core_Util::intArrayToString($outArray);
    }

    /**
     * Initialize a hashing context for BLAKE2b.
     *
     * @param string $key
     * @param int $outputLength
     * @return string
     * @throws Exception
     */
    public static function generichash_init($key = '', $outputLength = 32)
    {
        ParagonIE_Sodium_Core_BLAKE2b::pseudoConstructor();

        $k = null;
        if (!empty($key)) {
            $k = ParagonIE_Sodium_Core_BLAKE2b::stringToSplFixedArray($key);
            if ($k->count() > ParagonIE_Sodium_Core_BLAKE2b::KEYBYTES) {
                throw new Exception('Invalid key size');
            }
        }

        $ctx = ParagonIE_Sodium_Core_BLAKE2b::init($k, $outputLength);
        return ParagonIE_Sodium_Core_BLAKE2b::contextToString($ctx);
    }

    /**
     * Update a hashing context for BLAKE2b with $message
     *
     * @param string $ctx
     * @param string $message
     * @return string
     */
    public static function generichash_update($ctx, $message)
    {
        ParagonIE_Sodium_Core_BLAKE2b::pseudoConstructor();
        $in = ParagonIE_Sodium_Core_BLAKE2b::stringToSplFixedArray($message);
        $context = ParagonIE_Sodium_Core_BLAKE2b::stringToContext($ctx);
        ParagonIE_Sodium_Core_BLAKE2b::update($context, $in, $in->count());
        return ParagonIE_Sodium_Core_BLAKE2b::contextToString($context);
    }

    /**
     * Libsodium's crypto_kx().
     *
     * @param string $my_sk
     * @param string $their_pk
     * @param string $client_pk
     * @param string $server_pk
     * @return string
     */
    public static function kx($my_sk, $their_pk, $client_pk, $server_pk)
    {
        return self::generichash(
            self::scalarmult($my_sk, $their_pk) .
            $client_pk .
            $server_pk
        );
    }

    /**
     * ECDH over Curve25519
     *
     * @param string $sKey
     * @param string $pKey
     * @return string
     */
    public static function scalarmult($sKey, $pKey)
    {
        return ParagonIE_Sodium_Core_X25519::crypto_scalarmult_curve25519_ref10($sKey, $pKey);
    }

    /**
     * ECDH over Curve25519, using the basepoint.
     * Used to get a secret key from a public key.
     *
     * @param string $secret
     * @return string
     */
    public static function scalarmult_base($secret)
    {
        return ParagonIE_Sodium_Core_X25519::crypto_scalarmult_curve25519_ref10_base($secret);
    }

    /**
     * Xsalsa20-Poly1305 authenticated symmetric-key encryption.
     *
     * @param string $plaintext
     * @param string $nonce
     * @param string $key
     * @return string
     */
    public static function secretbox($plaintext, $nonce, $key)
    {
        $subkey = ParagonIE_Sodium_Core_HSalsa20::hsalsa20($nonce, $key);

        $block0 = str_repeat("\x00", 32);
        $mlen = ParagonIE_Sodium_Core_Util::strlen($plaintext);
        $mlen0 = $mlen;
        if ($mlen0 > 64 - self::secretbox_xsalsa20poly1305_ZEROBYTES) {
            $mlen0 = 64 - self::secretbox_xsalsa20poly1305_ZEROBYTES;
        }
        $block0 .= ParagonIE_Sodium_Core_Util::substr($plaintext, 0, $mlen0);
        $block0 = ParagonIE_Sodium_Core_Salsa20::salsa20_xor(
            $block0,
            ParagonIE_Sodium_Core_Util::substr($nonce, 16, 8),
            $subkey
        );
        $state = new ParagonIE_Sodium_Core_Poly1305_State(
            ParagonIE_Sodium_Core_Util::substr(
                $block0,
                0,
                self::onetimeauth_poly1305_KEYBYTES
            )
        );

        $c = ParagonIE_Sodium_Core_Util::substr(
            $block0,
            self::secretbox_xsalsa20poly1305_ZEROBYTES
        );
        if ($mlen > $mlen0) {
            $c .= ParagonIE_Sodium_Core_Salsa20::salsa20_xor_ic(
                ParagonIE_Sodium_Core_Util::substr(
                    $plaintext,
                    self::secretbox_xsalsa20poly1305_ZEROBYTES
                ),
                ParagonIE_Sodium_Core_Util::substr($nonce, 16, 8),
                1,
                $subkey
            );
        }
        try {
            ParagonIE_Sodium_Compat::memzero($block0);
            ParagonIE_Sodium_Compat::memzero($subkey);
        } catch (Error $ex) {
            $block0 = null;
            $subkey = null;
        }

        $state->update($c);
        $c = $state->finish() . $c;
        unset($state);

        return $c;
    }

    /**
     * Decrypt a ciphertext generated via secretbox().
     *
     * @param string $ciphertext
     * @param string $nonce
     * @param string $key
     * @return string
     * @throws Exception
     */
    public static function secretbox_open($ciphertext, $nonce, $key)
    {
        $mac = ParagonIE_Sodium_Core_Util::substr(
            $ciphertext,
            0,
            self::box_curve25519xsalsa20poly1305_MACBYTES
        );
        $c = ParagonIE_Sodium_Core_Util::substr(
            $ciphertext,
            self::box_curve25519xsalsa20poly1305_MACBYTES
        );
        $clen = ParagonIE_Sodium_Core_Util::strlen($c);

        $subkey = ParagonIE_Sodium_Core_HSalsa20::hsalsa20($nonce, $key);
        $block0 = ParagonIE_Sodium_Core_Salsa20::salsa20(
            64,
            ParagonIE_Sodium_Core_Util::substr($nonce, 16, 8),
            $subkey
        );
        if (!ParagonIE_Sodium_Core_Poly1305::onetimeauth_verify($mac, $c, $block0)) {
            try {
                ParagonIE_Sodium_Compat::memzero($subkey);
            } catch (Error $ex) {
                $subkey = null;
            }
            throw new Exception('Invalid MAC');
        }

        $m = ParagonIE_Sodium_Core_Util::xorStrings(
            ParagonIE_Sodium_Core_Util::substr($block0, self::secretbox_xsalsa20poly1305_ZEROBYTES),
            ParagonIE_Sodium_Core_Util::substr($c, 0, self::secretbox_xsalsa20poly1305_ZEROBYTES)
        );
        if ($clen > self::secretbox_xsalsa20poly1305_ZEROBYTES) {
            $m .= ParagonIE_Sodium_Core_Salsa20::salsa20_xor_ic(
                ParagonIE_Sodium_Core_Util::substr(
                    $c,
                    self::secretbox_xsalsa20poly1305_ZEROBYTES
                ),
                ParagonIE_Sodium_Core_Util::substr($nonce, 16, 8),
                1,
                $subkey
            );
        }
        return $m;
    }

    /**
     * Detached Ed25519 signature.
     *
     * @param string $message
     * @param string $sk
     * @return string
     */
    public static function sign_detached($message, $sk)
    {
        return ParagonIE_Sodium_Core_Ed25519::sign_detached($message, $sk);
    }

    /**
     * Attached Ed25519 signature. (Returns a signed message.)
     *
     * @param string $message
     * @param string $sk
     * @return string
     */
    public static function sign($message, $sk)
    {
        return ParagonIE_Sodium_Core_Ed25519::sign($message, $sk);
    }

    /**
     * Opens a signed message. If valid, returns the message.
     *
     * @param string $signedMessage
     * @param string $pk
     * @return string
     */
    public static function sign_open($signedMessage, $pk)
    {
        return ParagonIE_Sodium_Core_Ed25519::sign_open($signedMessage, $pk);
    }

    /**
     * Verify a detached signature of a given message and public key.
     *
     * @param string $signature
     * @param string $message
     * @param string $pk
     * @return bool
     */
    public static function sign_verify_detached($signature, $message, $pk)
    {
        return ParagonIE_Sodium_Core_Ed25519::verify_detached($signature, $message, $pk);
    }
}
