<?php
declare(strict_types=1);

if (class_exists('ParagonIE_Sodium_Core_Ed25519', false)) {
    return;
}
if (!class_exists('ParagonIE_Sodium_Core_Curve25519', false)) {
    require_once dirname(__FILE__) . '/Curve25519.php';
}

/**
 * Class ParagonIE_Sodium_Core_Ed25519
 */
abstract class ParagonIE_Sodium_Core_Ed25519 extends ParagonIE_Sodium_Core_Curve25519
{
    const KEYPAIR_BYTES = 96;
    const SEED_BYTES = 32;
    const SCALAR_BYTES = 32;

    /**
     * @internal You should not use this directly from another application
     *
     * @return string (96 bytes)
     * @throws Exception
     * @throws SodiumException
     * @throws TypeError
     */
    public static function keypair(): string
    {
        $seed = random_bytes(self::SEED_BYTES);
        $pk = '';
        $sk = '';
        self::seed_keypair($pk, $sk, $seed);
        return $sk . $pk;
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param string $pk
     * @param string $sk
     * @param string $seed
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function seed_keypair(
        string &$pk,
        string &$sk,
        #[SensitiveParameter]
        string $seed
    ): string {
        if (self::strlen($seed) !== self::SEED_BYTES) {
            throw new RangeException('crypto_sign keypair seed must be 32 bytes long');
        }
        $pk = self::publickey_from_secretkey($seed);
        $sk = $seed . $pk;
        return $sk;
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param string $keypair
     * @return string
     * @throws TypeError
     */
    public static function secretkey(
        #[SensitiveParameter]
        string $keypair
    ): string {
        if (self::strlen($keypair) !== self::KEYPAIR_BYTES) {
            throw new RangeException('crypto_sign keypair must be 96 bytes long');
        }
        return self::substr($keypair, 0, 64);
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param string $keypair
     * @return string
     * @throws TypeError
     */
    public static function publickey(
        #[SensitiveParameter]
        string $keypair
    ): string {
        if (self::strlen($keypair) !== self::KEYPAIR_BYTES) {
            throw new RangeException('crypto_sign keypair must be 96 bytes long');
        }
        return self::substr($keypair, 64, 32);
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param string $sk
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function publickey_from_secretkey(
        #[SensitiveParameter]
        string $sk
    ): string {
        /** @var string $sk */
        $sk = hash('sha512', self::substr($sk, 0, 32), true);
        $sk[0] = self::intToChr(
            self::chrToInt($sk[0]) & 248
        );
        $sk[31] = self::intToChr(
            (self::chrToInt($sk[31]) & 63) | 64
        );
        return self::sk_to_pk($sk);
    }

    /**
     * @param string $pk
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function pk_to_curve25519(
        string $pk
    ): string {
        if (self::small_order($pk)) {
            throw new SodiumException('Public key is on a small order');
        }
        $A = self::ge_frombytes_negate_vartime(self::substr($pk, 0, 32));
        $p1 = self::ge_mul_l($A);
        if (!self::fe_isnonzero($p1->X)) {
            throw new SodiumException('Unexpected zero result');
        }
        $one_minux_y = self::fe_invert(
            self::fe_sub(
                self::fe_1(),
                $A->Y
            )
        );
        $x = self::fe_mul(
            self::fe_add(self::fe_1(), $A->Y),
            $one_minux_y
        );
        return self::fe_tobytes($x);
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param string $sk
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function sk_to_pk(
        #[SensitiveParameter]
        string $sk
    ): string {
        return self::ge_p3_tobytes(
            self::ge_scalarmult_base(
                self::substr($sk, 0, 32)
            )
        );
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param string $message
     * @param string $sk
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function sign(
        string $message,
        #[SensitiveParameter]
        string $sk
    ): string {
        $signature = self::sign_detached($message, $sk);
        return $signature . $message;
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param string $message A signed message
     * @param string $pk      Public key
     * @return string         Message (without signature)
     * @throws SodiumException
     * @throws TypeError
     */
    public static function sign_open(
        string $message,
        string $pk
    ): string {
        $signature = self::substr($message, 0, 64);

        /** @var string $message */
        $message = self::substr($message, 64);

        if (self::verify_detached($signature, $message, $pk)) {
            return $message;
        }
        throw new SodiumException('Invalid signature');
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param string $message
     * @param string $sk
     * @return string
     * @throws SodiumException
     * @throws TypeError
     */
    public static function sign_detached(
        string $message,
        #[SensitiveParameter]
        string $sk
    ): string {
        $az =  hash('sha512', self::substr($sk, 0, 32), true);

        $az[0] = self::intToChr(self::chrToInt($az[0]) & 248);
        $az[31] = self::intToChr((self::chrToInt($az[31]) & 63) | 64);

        $hs = hash_init('sha512');
        hash_update($hs, self::substr($az, 32, 32));
        hash_update($hs, $message);
        $nonceHash = hash_final($hs, true);

        $pk = self::substr($sk, 32, 32);

        $nonce = self::sc_reduce($nonceHash) . self::substr($nonceHash, 32);
        $sig = self::ge_p3_tobytes(
            self::ge_scalarmult_base($nonce)
        );

        $hs = hash_init('sha512');
        hash_update($hs, self::substr($sig, 0, 32));
        hash_update($hs, self::substr($pk, 0, 32));
        hash_update($hs, $message);
        $hramHash = hash_final($hs, true);

        $hram = self::sc_reduce($hramHash);
        $sigAfter = self::sc_muladd($hram, $az, $nonce);
        $sig = self::substr($sig, 0, 32) . self::substr($sigAfter, 0, 32);

        try {
            ParagonIE_Sodium_Compat::memzero($az);
        } catch (SodiumException) {
            $az = null;
        }
        return $sig;
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param string $sig
     * @param string $message
     * @param string $pk
     * @return bool
     * @throws SodiumException
     * @throws TypeError
     */
    public static function verify_detached(
        string $sig,
        string $message,
        string $pk
    ): bool {
        if (self::strlen($sig) < 64) {
            throw new SodiumException('Signature is too short');
        }
        if ((self::chrToInt($sig[63]) & 240) && self::check_S_lt_L(self::substr($sig, 32, 32))) {
            throw new SodiumException('S < L - Invalid signature');
        }
        if (self::small_order($sig)) {
            throw new SodiumException('Signature is on too small of an order');
        }
        if ((self::chrToInt($sig[63]) & 224) !== 0) {
            throw new SodiumException('Invalid signature');
        }
        $d = 0;
        for ($i = 0; $i < 32; ++$i) {
            $d |= self::chrToInt($pk[$i]);
        }
        if ($d === 0) {
            throw new SodiumException('All zero public key');
        }

        /* The original value of ParagonIE_Sodium_Compat::$fastMult */
        $orig = ParagonIE_Sodium_Compat::$fastMult;

        // Set ParagonIE_Sodium_Compat::$fastMult to true to speed up verification.
        ParagonIE_Sodium_Compat::$fastMult = true;

        $A = self::ge_frombytes_negate_vartime($pk);

        $hDigest = hash(
            'sha512',
            self::substr($sig, 0, 32) .
                self::substr($pk, 0, 32) .
                $message,
            true
        );
        $h = self::sc_reduce($hDigest) . self::substr($hDigest, 32);
        $R = self::ge_double_scalarmult_vartime(
            $h,
            $A,
            self::substr($sig, 32)
        );
        $rcheck = self::ge_tobytes($R);

        // Reset ParagonIE_Sodium_Compat::$fastMult to what it was before.
        ParagonIE_Sodium_Compat::$fastMult = $orig;

        return self::verify_32($rcheck, self::substr($sig, 0, 32));
    }

    /**
     * @internal You should not use this directly from another application
     *
     * @param string $S
     * @return bool
     * @throws SodiumException
     * @throws TypeError
     */
    public static function check_S_lt_L(string $S): bool
    {
        if (self::strlen($S) < 32) {
            throw new SodiumException('Signature must be 32 bytes');
        }
        $L = array(
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
        );
        $c = 0;
        $n = 1;
        $i = 32;

        /** @var array<int, int> $L */
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
     * @param string $R
     * @return bool
     * @throws SodiumException
     * @throws TypeError
     */
    public static function small_order(string $R): bool
    {
        /** @var array<int, array<int, int>> $blocklist */
        $blocklist = array(
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
        $countBlocklist = count($blocklist);
        for ($i = 0; $i < $countBlocklist; ++$i) {
            $c = 0;
            for ($j = 0; $j < 32; ++$j) {
                $c |= self::chrToInt($R[$j]) ^ $blocklist[$i][$j];
            }
            if ($c === 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param string $s
     * @return string
     * @throws SodiumException
     */
    public static function scalar_complement(
        #[SensitiveParameter]
        string $s
    ): string {
        $t_ = self::L . str_repeat("\x00", 32);
        sodium_increment($t_);
        $s_ = $s . str_repeat("\x00", 32);
        ParagonIE_Sodium_Compat::sub($t_, $s_);
        return self::sc_reduce($t_);
    }

    /**
     * @return string
     * @throws SodiumException
     */
    public static function scalar_random(): string
    {
        do {
            $r = ParagonIE_Sodium_Compat::randombytes_buf(self::SCALAR_BYTES);
            $r[self::SCALAR_BYTES - 1] = self::intToChr(
                self::chrToInt($r[self::SCALAR_BYTES - 1]) & 0x1f
            );
        } while (
            !self::check_S_lt_L($r) || ParagonIE_Sodium_Compat::is_zero($r)
        );
        return $r;
    }

    /**
     * @param string $s
     * @return string
     * @throws SodiumException
     */
    public static function scalar_negate(
        #[SensitiveParameter]
        string $s
    ): string {
        $t_ = self::L . str_repeat("\x00", 32) ;
        $s_ = $s . str_repeat("\x00", 32) ;
        ParagonIE_Sodium_Compat::sub($t_, $s_);
        return self::sc_reduce($t_);
    }

    /**
     * @param string $a
     * @param string $b
     * @return string
     * @throws SodiumException
     */
    public static function scalar_add(
        #[SensitiveParameter]
        string $a,
        #[SensitiveParameter]
        string $b
    ): string {
        $a_ = $a . str_repeat("\x00", 32);
        $b_ = $b . str_repeat("\x00", 32);
        ParagonIE_Sodium_Compat::add($a_, $b_);
        return self::sc_reduce($a_);
    }

    /**
     * @param string $x
     * @param string $y
     * @return string
     * @throws SodiumException
     */
    public static function scalar_sub(
        #[SensitiveParameter]
        string $x,
        #[SensitiveParameter]
        string $y
    ): string {
        $yn = self::scalar_negate($y);
        return self::scalar_add($x, $yn);
    }
}
