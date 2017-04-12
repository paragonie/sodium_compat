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

> The code is currently frozen, pending the results of the [cryptography audit](https://github.com/paragonie/sodium_compat/issues/8).

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

## PHP 7.2 Polyfill

As per the [second vote on the libsodium RFC](https://wiki.php.net/rfc/libsodium#proposed_voting_choices),
PHP 7.2 uses `sodium_*` instead of `\Sodium\*`.

```php
<?php
require_once "/path/to/sodium_compat/autoload.php";

$alice_kp = sodium_crypto_sign_keypair();
$alice_sk = sodium_crypto_sign_secretkey($alice_kp);
$alice_pk = sodium_crypto_sign_publickey($alice_kp);

$message = 'This is a test message.';
$signature = sodium_crypto_sign_detached($message, $alice_sk);
if (sodium_crypto_sign_verify_detached($signature, $message, $alice_pk)) {
    echo 'OK', PHP_EOL;
} else {
    throw new Exception('Invalid signature');
}
```

Since this doesn't require a namespace, this API *is* exposed on PHP 5.2.

## General-Use Polyfill

If your users are on PHP < 5.3, or you want to write code that will work
whether or not the PECL extension is available, you'll want to use the
**`ParagonIE_Sodium_Compat`** class for most of your libsodium needs.

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

Since version 0.7.0, we have our own namespaced API (`ParagonIE\Sodium\*`) to allow brevity
in software that uses PHP 5.3+. This is useful if you want to use our file cryptography 
features without writing `ParagonIE_Sodium_File` every time. This is not exposed on PHP < 5.3,
so if your project supports PHP < 5.3, use the underscore method instead.

To learn how to use Libsodium, read [*Using Libsodium in PHP Projects*](https://paragonie.com/book/pecl-libsodium).

## Help, Sodium_Compat is Slow! How can I make it fast?

There are three ways to make it fast:

1. Use PHP 7.2 when it comes out, and take advantage of libsodium in the core.
2. Install the libsodium PHP extension from PECL.
3. Only if the previous two options are not available for you:
   1. Verify that [the processor you're using actually implements constant-time multiplication](https://bearssl.org/ctmul.html).
      Sodium_compat does, but it trades some speed for cross-platform security.
   2. Only if you are 100% certain that your processor is safe, you can set `ParagonIE_Sodium_Compat::$fastMul = true;`
      without harming the security of your cryptography keys. If your processor *isn't* safe, then decide whether you
      want speed or security because you can't have both.

## API Coverage

* Mainline NaCl Features
    * `crypto_auth()`
    * `crypto_auth_verify()`
    * `crypto_box()`
    * `crypto_box_open()`
    * `crypto_scalarmult()`
    * `crypto_secretbox()`
    * `crypto_secretbox_open()`
    * `crypto_sign()`
    * `crypto_sign_open()`
* PECL Libsodium Features
    * `crypto_aead_chacha20poly1305_encrypt()`
    * `crypto_aead_chacha20poly1305_decrypt()`
    * `crypto_aead_chacha20poly1305_ietf_encrypt()`
    * `crypto_aead_chacha20poly1305_ietf_decrypt()`
    * `crypto_aead_xchacha20poly1305_ietf_encrypt()`
    * `crypto_aead_xchacha20poly1305_ietf_decrypt()`
    * `crypto_box_xchacha20poly1305()`
    * `crypto_box_xchacha20poly1305_open()`
    * `crypto_box_seal()`
    * `crypto_box_seal_open()`
    * `crypto_generichash()`
    * `crypto_generichash_init()`
    * `crypto_generichash_update()`
    * `crypto_generichash_final()`
    * `crypto_kx()`
    * `crypto_secretbox_xchacha20poly1305()`
    * `crypto_secretbox_xchacha20poly1305_open()`
    * `crypto_shorthash()`
    * `crypto_sign_detached()`
    * `crypto_sign_verify_detached()`
    * For advanced users only:
        * `crypto_stream()`
        * `crypto_stream_xor()`
    * Other utilities (e.g. `crypto_*_keypair()`)

### Cryptography Primitives Provided

* **X25519** - Elliptic Curve Diffie Hellman over Curve25519
* **Ed25519** - Edwards curve Digital Signature Algorithm over Curve25519
* **Xsalsa20** - Extended-nonce Salsa20 stream cipher
* **ChaCha20** - Stream cipher
* **Xchacha20** - Extended-nonce ChaCha20 stream cipher
* **Poly1305** - Polynomial Evaluation Message Authentication Code modulo 2^130 - 5
* **BLAKE2b** - Cryptographic Hash Function
* **SipHash-2-4** - Fast hash, but not collision-resistant; ideal for hash tables.

### Features Excluded from this Polyfill

* `\Sodium\memzero()` - Although we expose this API endpoint, we can't reliably
  zero buffers from PHP.
  
  If you have the PHP extension installed, sodium_compat
  will use the native implementation to zero out the string provided. Otherwise
  it will throw an `Error` (provided as part of the random_compat polyfill).
* `\Sodium\crypto_pwhash()` - It's not feasible to polyfill scrypt or Argon2
  into PHP and get reasonable performance. Users would feel motivated to select
  parameters that downgrade security to avoid denial of service (DoS) attacks.
  
  The only winning move is not to play.
