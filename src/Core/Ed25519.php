<?php

/**
 * Class ParagonIE_Sodium_Core_Ed25519
 */
class ParagonIE_Sodium_Core_Ed25519 extends ParagonIE_Sodium_Core_Curve25519
{
    const KEYPAIR_BYTES = 96;
    const SEED_BYTES = 32;

    /**
     * @return string (96 bytes)
     */
    public static function keypair()
    {
        $seed = random_bytes(32);
        $pk = '';
        $sk = '';
        self::seed_keypair($pk, $sk, $seed);
        return $sk . $pk . $pk;
    }

    /**
     * @param string $pk
     * @param string $sk
     * @param string $seed
     */
    public static function seed_keypair(&$pk, &$sk, $seed)
    {
        if (self::strlen($seed) !== self::SEED_BYTES) {
            throw new RangeException('crypto_sign keypair seed must be 32 bytes long');
        }
        $sk = hash('sha512', $seed, true);
        $sk[0] = self::intToChr(
            self::chrToInt($sk[0]) & 248
        );
        $sk[31] = self::intToChr(
            (self::chrToInt($sk[31]) & 63) | 64
        );

        $pk = self::publickey_from_secretkey($sk);
        $sk = self::substr($sk, 0, 32) . $pk;
    }

    /**
     * @param string $keypair
     * @return string
     */
    public static function secretkey($keypair)
    {
        if (self::strlen($keypair) !== self::KEYPAIR_BYTES) {
            throw new RangeException('crypto_sign keypair seed must be 32 bytes long');
        }
        return self::substr($keypair, 0, 64);
    }

    /**
     * @param string $keypair
     * @return string
     */
    public static function publickey($keypair)
    {
        if (self::strlen($keypair) !== self::KEYPAIR_BYTES) {
            throw new RangeException('crypto_sign keypair seed must be 32 bytes long');
        }
        return self::substr($keypair, 64);
    }

    /**
     * @param $sk
     * @return string
     */
    public static function publickey_from_secretkey($sk)
    {
        return self::ge_p3_tobytes(
            self::ge_scalarmult_base($sk)
        );
    }

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
        if (self::strlen($sig) < 64) {
            throw new Exception('Signature is too short');
        }
        if (self::check_S_lt_L(self::substr($sig, 32, 32))) {
            throw new Exception('S < L - Invalid signature');
        }
        if (self::small_order($sig)) {
            throw new Exception('Signature is on too small of an order');
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
        if (self::strlen($S) < 32) {
            throw new Exception('Signature must be 32 bytes');
        }
        static $L = array(
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
        );
        $c = 0;
        $n = 1;
        $i = 32;

        do {
            --$i;
            $x = self::chrToInt($S[$i]);
            $c |= (
                (($x - $L[$i]) >> 8) & $n
            );
            $n &= (
                (($x ^ $L[$i]) - 1) >> 8
            );
        } while ($i !== 0);

        return $c === 0;
    }

    /**
     * @param string $sig
     * @return bool
     */
    public static function small_order($R)
    {
        static $blacklist = array(
            /* 0 (order 4) */
            array(
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ),
            /* 1 (order 1) */
            array(
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ),
            /* 2707385501144840649318225287225658788936804267575313519463743609750303402022 (order 8) */
            array(
                0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0,
                0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
                0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39,
                0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05
            ),
            /* 55188659117513257062467267217118295137698188065244968500265048394206261417927 (order 8) */
            array(
                0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f,
                0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
                0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6,
                0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a
            ),
            /* p-1 (order 2) */
            array(
                0x13, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0,
                0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
                0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39,
                0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x85
            ),
            /* p (order 4) */
            array(
                0xb4, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f,
                0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
                0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6,
                0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0xfa
            ),
            /* p+1 (order 1) */
            array(
                0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
            ),
            /* p+2707385501144840649318225287225658788936804267575313519463743609750303402022 (order 8) */
            array(
                0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
            ),
            /* p+55188659117513257062467267217118295137698188065244968500265048394206261417927 (order 8) */
            array(
                0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
            ),
            /* 2p-1 (order 2) */
            array(
                0xd9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
            ),
            /* 2p (order 4) */
            array(
                0xda, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
            ),
            /* 2p+1 (order 1) */
            array(
                0xdb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
            )
        );
        $countBlacklist = count($blacklist);

        for ($i = 0; $i < $countBlacklist; ++$i) {
            $c = 0;
            for ($j = 0; $j < 32; ++$j) {
                $c |= self::chrToInt($R[$j]) ^ $blacklist[$i][$j];
            }
            if ($c === 0) {
                return true;
            }
        }
        return false;
    }
}
