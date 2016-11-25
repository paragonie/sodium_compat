<?php

/**
 * Class ParagonIE_Sodium_Core_Ed25519
 */
class ParagonIE_Sodium_Core_Ed25519 extends ParagonIE_Sodium_Core_Curve25519
{
    /**
     * @param string $message
     * @param string $sk
     * @return string
     */
    public static function sign($message, $sk)
    {
        $signature = self::sign_detached($message, $sk);
        return $signature . $message;
    }
    /**
     * @param string $message
     * @param string $pk
     * @return string
     * @throws Exception
     */
    public static function sign_open($message, $pk)
    {
        $signature = self::substr($message, 0, 64);
        $message = self::substr($message, 64);
        if (self::verify_detached($signature, $message, $pk)) {
            return $message;
        }
        throw new Exception('Invalid signature');
    }

    /**
     * @param string $message
     * @param string $sk
     * @return string
     */
    public static function sign_detached($message, $sk)
    {
        # crypto_hash_sha512(az, sk, 32);
        $az =  hash('sha512', self::substr($sk, 0, 32), true);

        # az[0] &= 248;
        # az[31] &= 63;
        # az[31] |= 64;
        $az[0] = self::intToChr(self::chrToInt($az[0]) & 248);
        $az[31] = self::intToChr((self::chrToInt($az[31]) & 63) | 64);

        # crypto_hash_sha512_init(&hs);
        # crypto_hash_sha512_update(&hs, az + 32, 32);
        # crypto_hash_sha512_update(&hs, m, mlen);
        # crypto_hash_sha512_final(&hs, nonce);
        $hs = hash_init('sha512');
        hash_update($hs, self::substr($az, 32, 32));
        hash_update($hs, $message);
        $nonceHash = hash_final($hs, true);

        # memmove(sig + 32, sk + 32, 32);
        $pk = self::substr($sk, 32, 32);

        # sc_reduce(nonce);
        # ge_scalarmult_base(&R, nonce);
        # ge_p3_tobytes(sig, &R);
        $nonce = self::sc_reduce($nonceHash) . self::substr($nonceHash, 32);
        $sig = self::ge_p3_tobytes(
            self::ge_scalarmult_base($nonce)
        );

        # crypto_hash_sha512_init(&hs);
        # crypto_hash_sha512_update(&hs, sig, 64);
        # crypto_hash_sha512_update(&hs, m, mlen);
        # crypto_hash_sha512_final(&hs, hram);
        $hs = hash_init('sha512');
        hash_update($hs, $sig);
        hash_update($hs, $pk);
        hash_update($hs, $message);
        $hramHash = hash_final($hs, true);

        # sc_reduce(hram);
        # sc_muladd(sig + 32, hram, az, nonce);
        $hram = self::sc_reduce($hramHash);
        $sigAfter = self::sc_muladd($hram, $az, $nonce);
        $sig = self::substr($sig, 0, 32) . self::substr($sigAfter, 0, 32);

        ParagonIE_Sodium_Compat::memzero($az);
        return $sig;
    }

    /**
     * @param string $sig
     * @param string $message
     * @param string $pk
     * @return bool
     * @throws Exception
     */
    public static function verify_detached($sig, $message, $pk)
    {
        if (self::check_S_lt_L(self::substr($sig, 32))) {
            throw new Exception('S < L - Invalid signature');
        }
        if (self::small_order($sig)) {
            throw new Exception('Signature is on to small of an order');
        }
        if ((self::chrToInt($sig[63]) & 224) !== 0) {
            throw new Exception('Invalid signature');
        }

        $A = self::ge_frombytes_negate_vartime($pk);
        $d = 0;
        for ($i = 0; $i < 32; ++$i) {
            $d |= self::chrToInt($pk[$i]);
        }
        if ($d === 0) {
            throw new \Exception('All zero public key');
        }

        $hDigest = hash('sha512', self::substr($sig, 0, 32) . $pk . $message, true);
        $h = self::sc_reduce($hDigest) . self::substr($hDigest, 32);
        $R = self::ge_double_scalarmult_vartime(
            $h,
            $A,
            self::substr($sig, 32)
        );
        $rcheck = self::ge_tobytes($R);
        return self::verify_32($rcheck, self::substr($sig, 0, 32));
    }

    /**
     * @param string $S
     * @return bool
     */
    public static function check_S_lt_L($S)
    {

    }

    /**
     * @param string $sig
     * @return bool
     */
    public static function small_order($sig)
    {

    }
}
