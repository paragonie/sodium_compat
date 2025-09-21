<?php

require __DIR__ . '/../vendor/autoload.php';

ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;

$fuzzableMethods = [
    'base642bin',
    'bin2hex',
    'compare',
    'crypto_aead_aegis128l_decrypt',
    'crypto_aead_aegis256_decrypt',
    'crypto_aead_aes256gcm_decrypt',
    'crypto_aead_chacha20poly1305_decrypt',
    'crypto_aead_chacha20poly1305_ietf_decrypt',
    'crypto_aead_xchacha20poly1305_ietf_decrypt',
    'crypto_auth',
    'crypto_auth_verify',
    'crypto_box',
    'crypto_box_seal',
    'crypto_box_seal_open',
    'crypto_box_open',
    'crypto_box_publickey',
    'crypto_box_publickey_from_secretkey',
    'crypto_box_secretkey',
    'crypto_box_seed_keypair',
    'crypto_generichash',
    'crypto_kdf_derive_from_key',
    'crypto_kx',
    'crypto_kx_seed_keypair',
    'crypto_scalarmult',
    'crypto_scalarmult_base',
    'crypto_secretbox',
    'crypto_secretbox_open',
    'crypto_secretbox_xchacha20poly1305',
    'crypto_secretbox_xchacha20poly1305_open',
    'crypto_shorthash',
    'crypto_sign',
    'crypto_sign_open',
    'crypto_sign_detached',
    'crypto_sign_verify_detached',
    'crypto_sign_ed25519_pk_to_curve25519',
    'crypto_sign_ed25519_sk_to_curve25519',
    'crypto_stream_xor',
    'crypto_stream_xchacha20_xor',
    'hex2bin',
    'increment',
    'is_zero',
    'memcmp',
    'pad',
    'unpad',
    'ristretto255_is_valid_point',
    'ristretto255_add',
    'ristretto255_sub',
    'ristretto255_from_hash',
    'ristretto255_scalar_invert',
    'ristretto255_scalar_negate',
    'ristretto255_scalar_complement',
    'ristretto255_scalar_add',
    'ristretto255_scalar_sub',
    'ristretto255_scalar_mul',
    'scalarmult_ristretto255',
    'scalarmult_ristretto255_base',
    'ristretto255_scalar_reduce',
    'sub',
];

function getRandomBytes(int $length): string
{
    if ($length <= 0) {
        return '';
    }
    return random_bytes($length);
}

/** @var PhpFuzzer\Config $config */
$config->setTarget(function(string $input) use ($fuzzableMethods) {
    $method = $fuzzableMethods[array_rand($fuzzableMethods)];

    $args = [];
    switch ($method) {
        case 'base642bin':
            $args = [
                $input,
                random_int(1, 7),
                ''
            ];
            break;
        case 'bin2hex':
        case 'ristretto255_is_valid_point':
        case 'is_zero':
            $args = [$input];
            break;
        case 'compare':
        case 'memcmp':
            $args = [$input, getRandomBytes(strlen($input))];
            break;
        case 'crypto_aead_aegis128l_decrypt':
            $args = [
                $input,
                getRandomBytes(random_int(0, 128)),
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_AEAD_AEGIS128L_NPUBBYTES),
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_AEAD_AEGIS128L_KEYBYTES)
            ];
            break;
        case 'crypto_aead_aegis256_decrypt':
            $args = [
                $input,
                getRandomBytes(random_int(0, 128)),
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_AEAD_AEGIS256_NPUBBYTES),
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_AEAD_AEGIS256_KEYBYTES)
            ];
            break;
        case 'crypto_aead_aes256gcm_decrypt':
            if (!ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_is_available()) {
                return;
            }
            $args = [
                $input,
                getRandomBytes(random_int(0, 128)),
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_AEAD_AES256GCM_NPUBBYTES),
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_AEAD_AES256GCM_KEYBYTES)
            ];
            break;
        case 'crypto_aead_chacha20poly1305_decrypt':
            $args = [
                $input,
                getRandomBytes(random_int(0, 128)),
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES),
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES)
            ];
            break;
        case 'crypto_aead_chacha20poly1305_ietf_decrypt':
            $args = [
                $input,
                getRandomBytes(random_int(0, 128)),
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES),
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES)
            ];
            break;
        case 'crypto_aead_xchacha20poly1305_ietf_decrypt':
            $args = [
                $input,
                getRandomBytes(random_int(0, 128)),
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES),
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES)
            ];
            break;
        case 'crypto_auth':
            $args = [
                $input,
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_AUTH_KEYBYTES)
            ];
            break;
        case 'crypto_auth_verify':
            $args = [
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_AUTH_BYTES),
                $input,
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_AUTH_KEYBYTES)
            ];
            break;
        case 'crypto_box_open':
        case 'crypto_box':
            $args = [
                $input,
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_BOX_NONCEBYTES),
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_BOX_KEYPAIRBYTES)
            ];
            break;
        case 'crypto_box_seal':
            $args = [
                $input,
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_BOX_PUBLICKEYBYTES)
            ];
            break;
        case 'crypto_box_seal_open':
            $args = [
                $input,
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_BOX_KEYPAIRBYTES)
            ];
            break;
        case 'crypto_box_publickey':
        case 'crypto_box_secretkey':
            $args = [getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_BOX_KEYPAIRBYTES)];
            break;
        case 'crypto_box_publickey_from_secretkey':
            $args = [getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_BOX_SECRETKEYBYTES)];
            break;
        case 'crypto_box_seed_keypair':
            $args = [getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_BOX_SEEDBYTES)];
            break;
        case 'crypto_generichash':
            $args = [
                $input,
                getRandomBytes(random_int(
                    ParagonIE_Sodium_Compat::CRYPTO_GENERICHASH_KEYBYTES_MIN,
                    ParagonIE_Sodium_Compat::CRYPTO_GENERICHASH_KEYBYTES_MAX
                )),
                random_int(
                    ParagonIE_Sodium_Compat::CRYPTO_GENERICHASH_BYTES_MIN,
                    ParagonIE_Sodium_Compat::CRYPTO_GENERICHASH_BYTES_MAX
                )
            ];
            break;
        case 'crypto_kdf_derive_from_key':
            $args = [
                random_int(
                    ParagonIE_Sodium_Compat::CRYPTO_KDF_BYTES_MIN,
                    ParagonIE_Sodium_Compat::CRYPTO_KDF_BYTES_MAX
                ),
                random_int(0, 1000),
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_KDF_CONTEXTBYTES),
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_KDF_KEYBYTES)
            ];
            break;
        case 'crypto_kx':
            $args = [
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_KX_SECRETKEYBYTES),
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_KX_PUBLICKEYBYTES),
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_KX_PUBLICKEYBYTES),
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_KX_PUBLICKEYBYTES)
            ];
            break;
        case 'crypto_kx_seed_keypair':
            $args = [getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_KX_SEEDBYTES)];
            break;
        case 'crypto_scalarmult':
            $args = [
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_SCALARMULT_SCALARBYTES),
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_SCALARMULT_BYTES)
            ];
            break;
        case 'crypto_scalarmult_base':
            $args = [getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_SCALARMULT_SCALARBYTES)];
            break;
        case 'crypto_secretbox_xchacha20poly1305_open':
        case 'crypto_secretbox_xchacha20poly1305':
        case 'crypto_secretbox_open':
        case 'crypto_secretbox':
            $args = [
                $input,
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_SECRETBOX_NONCEBYTES),
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_SECRETBOX_KEYBYTES)
            ];
            break;
        case 'crypto_shorthash':
            $args = [
                $input,
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_SHORTHASH_KEYBYTES)
            ];
            break;
        case 'crypto_sign_detached':
        case 'crypto_sign':
            $args = [
                $input,
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_SIGN_SECRETKEYBYTES)
            ];
            break;
        case 'crypto_sign_open':
            $args = [
                $input,
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_SIGN_PUBLICKEYBYTES)
            ];
            break;
        case 'crypto_sign_verify_detached':
            $args = [
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_SIGN_BYTES),
                $input,
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_SIGN_PUBLICKEYBYTES)
            ];
            break;
        case 'crypto_sign_ed25519_pk_to_curve25519':
            $args = [getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_SIGN_PUBLICKEYBYTES)];
            break;
        case 'crypto_sign_ed25519_sk_to_curve25519':
            $args = [getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_SIGN_SECRETKEYBYTES)];
            break;
        case 'crypto_stream_xor':
            $args = [
                $input,
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_STREAM_NONCEBYTES),
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_STREAM_KEYBYTES)
            ];
            break;
        case 'crypto_stream_xchacha20_xor':
            $args = [
                $input,
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_STREAM_XCHACHA20_NONCEBYTES),
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_STREAM_XCHACHA20_KEYBYTES)
            ];
            break;
        case 'hex2bin':
            $args = [$input, ''];
            break;
        case 'increment':
        case 'sub':
            $val = $input;
            $args = [&$val, getRandomBytes(strlen($input))];
            break;
        case 'pad':
        case 'unpad':
            $args = [$input, random_int(1, 1024)];
            break;
        case 'ristretto255_add':
        case 'ristretto255_sub':
        case 'scalarmult_ristretto255':
            $args = [
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_CORE_RISTRETTO255_BYTES),
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_CORE_RISTRETTO255_BYTES)
            ];
            break;
        case 'ristretto255_from_hash':
            $args = [getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_CORE_RISTRETTO255_HASHBYTES)];
            break;
        case 'ristretto255_scalar_invert':
        case 'ristretto255_scalar_negate':
        case 'ristretto255_scalar_complement':
        case 'scalarmult_ristretto255_base':
            $args = [getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_CORE_RISTRETTO255_SCALARBYTES)];
            break;
        case 'ristretto255_scalar_add':
        case 'ristretto255_scalar_sub':
        case 'ristretto255_scalar_mul':
            $args = [
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_CORE_RISTRETTO255_SCALARBYTES),
                getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_CORE_RISTRETTO255_SCALARBYTES)
            ];
            break;
        case 'ristretto255_scalar_reduce':
            $args = [getRandomBytes(ParagonIE_Sodium_Compat::CRYPTO_CORE_RISTRETTO255_NONREDUCEDSCALARBYTES)];
            break;
        default:
            // Should not happen
            return;
    }

    try {
        ParagonIE_Sodium_Compat::$method(...$args);
    } catch (SodiumException $e) {
        // Ignore sodium exceptions, as they are expected for invalid inputs.
    } catch (TypeError $e) {
        // Ignore type errors, as they are expected for invalid inputs.
    } catch (Error $e) {
        // Ignore errors, as they are expected for invalid inputs.
    }
});
