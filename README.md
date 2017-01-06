# Sodium Compat

[![Build Status](https://travis-ci.org/paragonie/sodium_compat.svg?branch=master)](https://travis-ci.org/paragonie/sodium_compat)
[![Latest Stable Version](https://poser.pugx.org/paragonie/sodium_compat/v/stable)](https://packagist.org/packages/paragonie/sodium_compat)
[![Latest Unstable Version](https://poser.pugx.org/paragonie/sodium_compat/v/unstable)](https://packagist.org/packages/paragonie/sodium_compat)
[![License](https://poser.pugx.org/paragonie/sodium_compat/license)](https://packagist.org/packages/paragonie/sodium_compat)

Sodium Compat is a pure PHP polyfill for the Sodium cryptography library 
(libsodium), otherwise [available in PECL](https://pecl.php.net/package/libsodium).

This library tentativeley supports PHP 5.2.4 - 7.x (latest), but officially
only supports [non-EOL'd versions of PHP](https://secure.php.net/supported-versions.php).

If you have the PHP extension installed, Sodium Compat will opportunistically
and transparently use the PHP extension instead of our implementation.

## IMPORTANT!

### ![Danger: Experimental](https://camo.githubusercontent.com/275bc882f21b154b5537b9c123a171a30de9e6aa/68747470733a2f2f7261772e6769746875622e636f6d2f63727970746f7370686572652f63727970746f7370686572652f6d61737465722f696d616765732f6578706572696d656e74616c2e706e67)

This is an **experimental** cryptography library. It has not been formally
audited by an independent third party that specializes in cryptography or
cryptanalysis.

Until it has received a clean bill of health from independent computer security
experts, **use this library at your own risk.** 

# Installing Sodium Compat

If you're using Composer:

```bash
composer require paragonie/sodium_compat
```

If you're not using Composer, download a [release tarball](https://github.com/paragonie/sodium_compat/releases)
(which should be signed with [our GnuPG public key](https://paragonie.com/static/gpg-public-key.txt)), extract
its contents, then include our `autoload.php` script in your project.

```php
<?php
require_once "/path/to/sodium_compat/autoload.php";
```

# Using Sodium Compat

## True Polyfill

If you're using PHP 5.3.0 or newer and do not have the PECL extension installed,
you can just use the [standard ext/sodium API features as-is](https://paragonie.com/book/pecl-libsodium)
and the polyfill will work its magic.

```php
<?php
require_once "/path/to/sodium_compat/autoload.php";

$alice_kp = \Sodium\crypto_sign_keypair();
$alice_sk = \Sodium\crypto_sign_secretkey($alice_kp);
$alice_pk = \Sodium\crypto_sign_publickey($alice_kp);

$message = 'This is a test message.';
$signature = \Sodium\crypto_sign_detached($message, $alice_sk);
if (\Sodium\crypto_sign_verify_detached($signature, $message, $alice_pk)) {
    echo 'OK', PHP_EOL;
} else {
    throw new Exception('Invalid signature');
}
```

The polyfill does not expose this API on PHP < 5.3, or if you have the PHP
extension installed already.

## General-Use Polyfill

If your users are on PHP < 5.3, or you want to write code that will work
whether or not the PECL extension is available, you'll want to use the
**`ParagonIE_Sodium_Compat`** class for all of your libsodium needs.

The above example, written for general use:

```php
<?php
require_once "/path/to/sodium_compat/autoload.php";

$alice_kp = ParagonIE_Sodium_Compat::crypto_sign_keypair();
$alice_sk = ParagonIE_Sodium_Compat::crypto_sign_secretkey($alice_kp);
$alice_pk = ParagonIE_Sodium_Compat::crypto_sign_publickey($alice_kp);

$message = 'This is a test message.';
$signature = ParagonIE_Sodium_Compat::crypto_sign_detached($message, $alice_sk);
if (ParagonIE_Sodium_Compat::crypto_sign_verify_detached($signature, $message, $alice_pk)) {
    echo 'OK', PHP_EOL;
} else {
    throw new Exception('Invalid signature');
}
```

Generally: If you replace `\Sodium\ ` with `ParagonIE_Sodium_Compat::`, any
code already written for the libsodium PHP extension should work with our
polyfill without additional code changes.

#### Libsodium Features Implemented and Tested

- [x] Ed25519: public key signatures (`crypto_sign`)
- [x] X25519: public key exchange (`crypto_scalarmult`)
- [x] Xsalsa20: unauthenticated secret-key encryption (`crypto_stream`)
- [x] Poly1305: one-time message authentication (`crypto_onetimeauth`)
- [x] Public-key authenticated encryption (`crypto_box`)
- [x] Secret-key authenticated encryption (`crypto_secretbox`)
- [x] Anonymous public-key encryption (`crypto_box_seal`)
- [x] SipHash: fast collision-resistant hashing (`crypto_shorthash`)
- [x] HMAC-SHA-512-256: Secret-key message authentication (`crypto_auth`)
- [x] BLAKE2b: Cryptographic hashing (`crypto_generichash`)
- [ ] Argon2i: Password hashing / key derivation (`crypto_pwhash`)
