<?php

if (!function_exists('sodium_crypto_kem_mlkem768_keypair')) {
    function sodium_crypto_kem_mlkem768_keypair(): string
    {
        return ParagonIE_Sodium_Compat::crypto_kem_mlkem768_keypair(true);
    }
}

if (!function_exists('sodium_crypto_kem_mlkem768_seed_keypair')) {
    /**
     * @throws SodiumException
     */
    function sodium_crypto_kem_mlkem768_seed_keypair(#[SensitiveParameter] string $seed): string
    {
        return ParagonIE_Sodium_Compat::crypto_kem_mlkem768_seed_keypair($seed, true);
    }
}

if (!function_exists('sodium_crypto_kem_mlkem768_secretkey')) {
    /**
     * @throws SodiumException
     */
    function sodium_crypto_kem_mlkem768_secretkey(#[SensitiveParameter] string $keypair): string
    {
        return ParagonIE_Sodium_Compat::crypto_kem_mlkem768_secretkey($keypair, true);
    }
}

if (!function_exists('sodium_crypto_kem_mlkem768_publickey')) {
    /**
     * @throws SodiumException
     */
    function sodium_crypto_kem_mlkem768_publickey(#[SensitiveParameter] string $keypair): string
    {
        return ParagonIE_Sodium_Compat::crypto_kem_mlkem768_publickey($keypair, true);
    }
}

if (!function_exists('sodium_crypto_kem_mlkem768_enc')) {
    function sodium_crypto_kem_mlkem768_enc(string $publicKey): array
    {
        return ParagonIE_Sodium_Compat::crypto_kem_mlkem768_enc($publicKey, true);
    }
}

if (!function_exists('sodium_crypto_kem_mlkem768_enc_deterministic')) {
    /**
     * @throws SodiumException
     */
    function sodium_crypto_kem_mlkem768_enc_deterministic(string $publicKey, #[SensitiveParameter] string $seed): array
    {
        return ParagonIE_Sodium_Compat::crypto_kem_mlkem768_enc_deterministic($publicKey, $seed, true);
    }
}

if (!function_exists('sodium_crypto_kem_mlkem768_dec')) {
    /**
     * @throws SodiumException
     */
    function sodium_crypto_kem_mlkem768_dec(string $ciphertext, #[SensitiveParameter] string $secretKey): string
    {
        return ParagonIE_Sodium_Compat::crypto_kem_mlkem768_dec($ciphertext, $secretKey, true);
    }
}

if (!function_exists('sodium_crypto_kem_xwing_keypair')) {
    function sodium_crypto_kem_xwing_keypair(): string
    {
        return ParagonIE_Sodium_Compat::crypto_kem_xwing_keypair(true);
    }
}

if (!function_exists('sodium_crypto_kem_xwing_seed_keypair')) {
    function sodium_crypto_kem_xwing_seed_keypair(#[SensitiveParameter] string $seed): string
    {
        return ParagonIE_Sodium_Compat::crypto_kem_xwing_seed_keypair($seed, true);
    }
}

if (!function_exists('sodium_crypto_kem_xwing_secretkey')) {
    /**
     * @throws SodiumException
     */
    function sodium_crypto_kem_xwing_secretkey(#[SensitiveParameter] string $keypair): string
    {
        return ParagonIE_Sodium_Compat::crypto_kem_xwing_secretkey($keypair, true);
    }
}

if (!function_exists('sodium_crypto_kem_xwing_publickey')) {
    /**
     * @throws SodiumException
     */
    function sodium_crypto_kem_xwing_publickey(#[SensitiveParameter] string $keypair): string
    {
        return ParagonIE_Sodium_Compat::crypto_kem_xwing_publickey($keypair, true);
    }
}

if (!function_exists('sodium_crypto_kem_xwing_enc')) {
    function sodium_crypto_kem_xwing_enc(string $publicKey): array
    {
        return ParagonIE_Sodium_Compat::crypto_kem_xwing_enc($publicKey, true);
    }
}

if (!function_exists('sodium_crypto_kem_xwing_enc_deterministic')) {
    function sodium_crypto_kem_xwing_enc_deterministic(string $publicKey, #[SensitiveParameter] string $seed): array
    {
        return ParagonIE_Sodium_Compat::crypto_kem_xwing_enc_deterministic($publicKey, $seed, true);
    }
}

if (!function_exists('sodium_crypto_kem_xwing_dec')) {
    function sodium_crypto_kem_xwing_dec(string $ciphertext, #[SensitiveParameter] string $secretKey): string
    {
        return ParagonIE_Sodium_Compat::crypto_kem_xwing_dec($ciphertext, $secretKey, true);
    }
}

if (!function_exists('sodium_crypto_kem_keypair')) {
    /**
     * @throws SodiumException
     */
    function sodium_crypto_kem_keypair(): string
    {
        return ParagonIE_Sodium_Compat::crypto_kem_keypair(true);
    }
}

if (!function_exists('sodium_crypto_kem_seed_keypair')) {
    /**
     * @throws SodiumException
     */
    function sodium_crypto_kem_seed_keypair(#[SensitiveParameter] string $seed): string
    {
        return ParagonIE_Sodium_Compat::crypto_kem_seed_keypair($seed, true);
    }
}

if (!function_exists('sodium_crypto_kem_secretkey')) {
    /**
     * @throws SodiumException
     */
    function sodium_crypto_kem_secretkey(#[SensitiveParameter] string $keypair): string
    {
        return ParagonIE_Sodium_Compat::crypto_kem_secretkey($keypair, true);
    }
}

if (!function_exists('sodium_crypto_kem_publickey')) {
    /**
     * @throws SodiumException
     */
    function sodium_crypto_kem_publickey(#[SensitiveParameter] string $keypair): string
    {
        return ParagonIE_Sodium_Compat::crypto_kem_publickey($keypair, true);
    }
}

if (!function_exists('sodium_crypto_kem_enc')) {
    /**
     * @throws SodiumException
     */
    function sodium_crypto_kem_enc(string $publicKey): array
    {
        return ParagonIE_Sodium_Compat::crypto_kem_enc($publicKey, true);
    }
}

if (!function_exists('sodium_crypto_kem_enc_deterministic')) {
    /**
     * @throws SodiumException
     */
    function sodium_crypto_kem_enc_deterministic(string $publicKey, #[SensitiveParameter] string $seed): array
    {
        return ParagonIE_Sodium_Compat::crypto_kem_enc_deterministic($publicKey, $seed, true);
    }
}

if (!function_exists('sodium_crypto_kem_dec')) {
    /**
     * @throws SodiumException
     */
    function sodium_crypto_kem_dec(string $ciphertext, #[SensitiveParameter] string $secretKey): string
    {
        return ParagonIE_Sodium_Compat::crypto_kem_dec($ciphertext, $secretKey, true);
    }
}

if (!function_exists('sodium_crypto_sign_mldsa44_keypair')) {
    function sodium_crypto_sign_mldsa44_keypair(): string
    {
        return ParagonIE_Sodium_Compat::crypto_sign_mldsa44_keypair(true);
    }
}

if (!function_exists('sodium_crypto_sign_mldsa44_seed_keypair')) {
    function sodium_crypto_sign_mldsa44_seed_keypair(#[SensitiveParameter] string $seed): string
    {
        return ParagonIE_Sodium_Compat::crypto_sign_mldsa44_seed_keypair($seed, true);
    }
}

if (!function_exists('sodium_crypto_sign_mldsa44_secretkey')) {
    /**
     * @throws SodiumException
     */
    function sodium_crypto_sign_mldsa44_secretkey(#[SensitiveParameter] string $keypair): string
    {
        return ParagonIE_Sodium_Compat::crypto_sign_mldsa44_secretkey($keypair, true);
    }
}

if (!function_exists('sodium_crypto_sign_mldsa44_publickey')) {
    /**
     * @throws SodiumException
     */
    function sodium_crypto_sign_mldsa44_publickey(#[SensitiveParameter] string $keypair): string
    {
        return ParagonIE_Sodium_Compat::crypto_sign_mldsa44_publickey($keypair, true);
    }
}

if (!function_exists('sodium_crypto_sign_mldsa44_detached')) {
    /**
     * @throws SodiumException
     */
    function sodium_crypto_sign_mldsa44_detached(string $message, #[SensitiveParameter] string $secretKey): string
    {
        return ParagonIE_Sodium_Compat::crypto_sign_mldsa44_detached($message, $secretKey, true);
    }
}

if (!function_exists('sodium_crypto_sign_mldsa44_detached_ctx')) {
    /**
     * @throws SodiumException
     */
    function sodium_crypto_sign_mldsa44_detached_ctx(string $message, string $context, #[SensitiveParameter] string $secretKey): string
    {
        return ParagonIE_Sodium_Compat::crypto_sign_mldsa44_detached_ctx($message, $context, $secretKey, true);
    }
}

if (!function_exists('sodium_crypto_sign_mldsa44_verify_detached')) {
    function sodium_crypto_sign_mldsa44_verify_detached(string $signature, string $message, string $publicKey): bool
    {
        return ParagonIE_Sodium_Compat::crypto_sign_mldsa44_verify_detached($signature, $message, $publicKey, true);
    }
}

if (!function_exists('sodium_crypto_sign_mldsa44_verify_detached_ctx')) {
    function sodium_crypto_sign_mldsa44_verify_detached_ctx(string $signature, string $message, string $context, string $publicKey): bool
    {
        return ParagonIE_Sodium_Compat::crypto_sign_mldsa44_verify_detached_ctx($signature, $message, $context, $publicKey, true);
    }
}

if (!defined('SODIUM_CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES')) {
    define('SODIUM_CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES', ParagonIE_Sodium_Compat::CRYPTO_KEM_MLKEM768_PUBLICKEYBYTES);
}
if (!defined('SODIUM_CRYPTO_KEM_MLKEM768_SECRETKEYBYTES')) {
    define('SODIUM_CRYPTO_KEM_MLKEM768_SECRETKEYBYTES', ParagonIE_Sodium_Compat::CRYPTO_KEM_MLKEM768_SECRETKEYBYTES);
}
if (!defined('SODIUM_CRYPTO_KEM_MLKEM768_SEEDBYTES')) {
    define('SODIUM_CRYPTO_KEM_MLKEM768_SEEDBYTES', ParagonIE_Sodium_Compat::CRYPTO_KEM_MLKEM768_SEEDBYTES);
}
if (!defined('SODIUM_CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES')) {
    define('SODIUM_CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES', ParagonIE_Sodium_Compat::CRYPTO_KEM_MLKEM768_CIPHERTEXTBYTES);
}
if (!defined('SODIUM_CRYPTO_KEM_MLKEM768_SHAREDSECRETBYTES')) {
    define('SODIUM_CRYPTO_KEM_MLKEM768_SHAREDSECRETBYTES', ParagonIE_Sodium_Compat::CRYPTO_KEM_MLKEM768_SHAREDSECRETBYTES);
}
if (!defined('SODIUM_CRYPTO_KEM_MLKEM768_KEYPAIRBYTES')) {
    define('SODIUM_CRYPTO_KEM_MLKEM768_KEYPAIRBYTES', ParagonIE_Sodium_Compat::CRYPTO_KEM_MLKEM768_KEYPAIRBYTES);
}
if (!defined('SODIUM_CRYPTO_KEM_XWING_PUBLICKEYBYTES')) {
    define('SODIUM_CRYPTO_KEM_XWING_PUBLICKEYBYTES', ParagonIE_Sodium_Compat::CRYPTO_KEM_XWING_PUBLICKEYBYTES);
}
if (!defined('SODIUM_CRYPTO_KEM_XWING_SECRETKEYBYTES')) {
    define('SODIUM_CRYPTO_KEM_XWING_SECRETKEYBYTES', ParagonIE_Sodium_Compat::CRYPTO_KEM_XWING_SECRETKEYBYTES);
}
if (!defined('SODIUM_CRYPTO_KEM_XWING_SEEDBYTES')) {
    define('SODIUM_CRYPTO_KEM_XWING_SEEDBYTES', ParagonIE_Sodium_Compat::CRYPTO_KEM_XWING_SEEDBYTES);
}
if (!defined('SODIUM_CRYPTO_KEM_XWING_CIPHERTEXTBYTES')) {
    define('SODIUM_CRYPTO_KEM_XWING_CIPHERTEXTBYTES', ParagonIE_Sodium_Compat::CRYPTO_KEM_XWING_CIPHERTEXTBYTES);
}
if (!defined('SODIUM_CRYPTO_KEM_XWING_SHAREDSECRETBYTES')) {
    define('SODIUM_CRYPTO_KEM_XWING_SHAREDSECRETBYTES', ParagonIE_Sodium_Compat::CRYPTO_KEM_XWING_SHAREDSECRETBYTES);
}
if (!defined('SODIUM_CRYPTO_KEM_XWING_KEYPAIRBYTES')) {
    define('SODIUM_CRYPTO_KEM_XWING_KEYPAIRBYTES', ParagonIE_Sodium_Compat::CRYPTO_KEM_XWING_KEYPAIRBYTES);
}
if (!defined('SODIUM_CRYPTO_KEM_PUBLICKEYBYTES')) {
    define('SODIUM_CRYPTO_KEM_PUBLICKEYBYTES', ParagonIE_Sodium_Compat::CRYPTO_KEM_PUBLICKEYBYTES);
}
if (!defined('SODIUM_CRYPTO_KEM_SECRETKEYBYTES')) {
    define('SODIUM_CRYPTO_KEM_SECRETKEYBYTES', ParagonIE_Sodium_Compat::CRYPTO_KEM_SECRETKEYBYTES);
}
if (!defined('SODIUM_CRYPTO_KEM_SEEDBYTES')) {
    define('SODIUM_CRYPTO_KEM_SEEDBYTES', ParagonIE_Sodium_Compat::CRYPTO_KEM_SEEDBYTES);
}
if (!defined('SODIUM_CRYPTO_KEM_CIPHERTEXTBYTES')) {
    define('SODIUM_CRYPTO_KEM_CIPHERTEXTBYTES', ParagonIE_Sodium_Compat::CRYPTO_KEM_CIPHERTEXTBYTES);
}
if (!defined('SODIUM_CRYPTO_KEM_SHAREDSECRETBYTES')) {
    define('SODIUM_CRYPTO_KEM_SHAREDSECRETBYTES', ParagonIE_Sodium_Compat::CRYPTO_KEM_SHAREDSECRETBYTES);
}
if (!defined('SODIUM_CRYPTO_KEM_KEYPAIRBYTES')) {
    define('SODIUM_CRYPTO_KEM_KEYPAIRBYTES', ParagonIE_Sodium_Compat::CRYPTO_KEM_KEYPAIRBYTES);
}
if (!defined('SODIUM_CRYPTO_KEM_PRIMITIVE')) {
    define('SODIUM_CRYPTO_KEM_PRIMITIVE', ParagonIE_Sodium_Compat::CRYPTO_KEM_PRIMITIVE);
}
if (!defined('SODIUM_CRYPTO_SIGN_MLDSA44_PUBLICKEYBYTES')) {
    define('SODIUM_CRYPTO_SIGN_MLDSA44_PUBLICKEYBYTES', ParagonIE_Sodium_Compat::CRYPTO_SIGN_MLDSA44_PUBLICKEYBYTES);
}
if (!defined('SODIUM_CRYPTO_SIGN_MLDSA44_SECRETKEYBYTES')) {
    define('SODIUM_CRYPTO_SIGN_MLDSA44_SECRETKEYBYTES', ParagonIE_Sodium_Compat::CRYPTO_SIGN_MLDSA44_SECRETKEYBYTES);
}
if (!defined('SODIUM_CRYPTO_SIGN_MLDSA44_SEEDBYTES')) {
    define('SODIUM_CRYPTO_SIGN_MLDSA44_SEEDBYTES', ParagonIE_Sodium_Compat::CRYPTO_SIGN_MLDSA44_SEEDBYTES);
}
if (!defined('SODIUM_CRYPTO_SIGN_MLDSA44_BYTES')) {
    define('SODIUM_CRYPTO_SIGN_MLDSA44_BYTES', ParagonIE_Sodium_Compat::CRYPTO_SIGN_MLDSA44_BYTES);
}
if (!defined('SODIUM_CRYPTO_SIGN_MLDSA44_KEYPAIRBYTES')) {
    define('SODIUM_CRYPTO_SIGN_MLDSA44_KEYPAIRBYTES', ParagonIE_Sodium_Compat::CRYPTO_SIGN_MLDSA44_KEYPAIRBYTES);
}
if (!defined('SODIUM_CRYPTO_SIGN_MLDSA44_CONTEXTBYTES_MAX')) {
    define('SODIUM_CRYPTO_SIGN_MLDSA44_CONTEXTBYTES_MAX', ParagonIE_Sodium_Compat::CRYPTO_SIGN_MLDSA44_CONTEXTBYTES_MAX);
}
if (!defined('SODIUM_CRYPTO_SIGN_MLDSA44_MESSAGEBYTES_MAX')) {
    define('SODIUM_CRYPTO_SIGN_MLDSA44_MESSAGEBYTES_MAX', ParagonIE_Sodium_Compat::CRYPTO_SIGN_MLDSA44_MESSAGEBYTES_MAX);
}
