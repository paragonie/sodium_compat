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
        $k = self::box_beforenm(
            self::box_secretkey($keypair),
            self::box_publickey($keypair)
        );
        $c = self::secretbox($plaintext, $nonce, $k);
        ParagonIE_Sodium_Compat::memzero($k);
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

        $c = self::box($message, $nonce, $keypair);
        ParagonIE_Sodium_Compat::memzero($ephemeralKeypairSK);
        ParagonIE_Sodium_Compat::memzero($nonce);
        return $ephemeralPK . $c;
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
        $c = ParagonIE_Sodium_Core_Util::substr($message, 32);

        $secretKey = self::box_secretkey($keypair);
        $publicKey = self::box_publickey($keypair);

        $nonce = self::generichash(
            $ephemeralPK . $publicKey,
            '',
            24
        );
        $keypair = self::box_keypair_from_secretkey_and_publickey($secretKey, $ephemeralPK);
        $m = self::box_open($c, $nonce, $keypair);
        ParagonIE_Sodium_Compat::memzero($secretKey);
        ParagonIE_Sodium_Compat::memzero($ephemeralPK);
        ParagonIE_Sodium_Compat::memzero($nonce);
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
        $s = self::scalarmult($sk, $pk);
        return ParagonIE_Sodium_Core_HSalsa20::hsalsa20(
            str_repeat("\x00", 16),
            $s
        );
    }

    /**
     * @return string
     */
    public static function box_keypair()
    {
        $sk = random_bytes(32);
        $pk = self::scalarmult_base($sk);
        return $sk . $pk;
    }

    /**
     * @param string $sk
     * @param string $pk
     * @return string
     */
    public static function box_keypair_from_secretkey_and_publickey($sk, $pk)
    {
        return ParagonIE_Sodium_Core_Util::substr($sk, 0, 32) .
            ParagonIE_Sodium_Core_Util::substr($pk, 0, 32);
    }

    /**
     * @param string $keypair
     * @return string
     */
    public static function box_secretkey($keypair)
    {
        if (ParagonIE_Sodium_Core_Util::strlen($keypair) !== 64) {
            throw new RangeException('Must be a keypair.');
        }
        return ParagonIE_Sodium_Core_Util::substr($keypair, 0, 32);
    }

    /**
     * @param string $keypair
     * @return string
     */
    public static function box_publickey($keypair)
    {
        if (ParagonIE_Sodium_Core_Util::strlen($keypair) !== 64) {
            throw new RangeException('Must be a keypair.');
        }
        return ParagonIE_Sodium_Core_Util::substr($keypair, 32, 32);
    }

    /**
     * @param $sk
     * @return string
     * @throws RangeException
     */
    public static function box_publickey_from_secretkey($sk)
    {
        if (ParagonIE_Sodium_Core_Util::strlen($sk) !== 32) {
            throw new RangeException('Must be 32 bytes long.');
        }
        return self::scalarmult_base($sk);
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
        $k = self::box_beforenm(
            self::box_secretkey($keypair),
            self::box_publickey($keypair)
        );
        $p = self::secretbox_open($ciphertext, $nonce, $k);
        ParagonIE_Sodium_Compat::memzero($k);
        return $p;
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
        return ParagonIE_Sodium_Core_Util::intArrayToString($out->toArray());
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
        return ParagonIE_Sodium_Core_Util::intArrayToString($out->toArray());
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
     * @param string $sk
     * @param string $pk
     * @return string
     */
    public static function scalarmult($sk, $pk)
    {
        return ParagonIE_Sodium_Core_X25519::crypto_scalarmult_curve25519_ref10($sk, $pk);
    }

    /**
     * ECDH over Curve25519, using the basepoint.
     * Used to get a secret key from a public key.
     *
     * @param string $n
     * @return string
     */
    public static function scalarmult_base($n)
    {
        return ParagonIE_Sodium_Core_X25519::crypto_scalarmult_curve25519_ref10_base($n);
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
        ParagonIE_Sodium_Compat::memzero($block0);
        ParagonIE_Sodium_Compat::memzero($subkey);

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
            ParagonIE_Sodium_Compat::memzero($subkey);
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
