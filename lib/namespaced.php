<?php

/*
 * This file is just for convenience, to allow developers to reduce verbosity when
 * they add this project to their libraries.
 *
 * Replace this:
 *
 * $x = ParagonIE_Sodium_Compat::crypto_aead_xchacha20poly1305_encrypt(...$args);
 *
 * with this:
 *
 * use ParagonIE\Sodium\Compat;
 *
 * $x = Compat::crypto_aead_xchacha20poly1305_encrypt(...$args);
 */
namespace ParagonIE\Sodium {
    class Compat extends \ParagonIE_Sodium_Compat
    {
    }

    class Crypto extends \ParagonIE_Sodium_Crypto
    {
    }

    class File extends \ParagonIE_Sodium_File
    {
    }
}

namespace ParagonIE\Sodium\Core {
    class BLAKE2b extends \ParagonIE_Sodium_Core_BLAKE2b
    {
    }

    class ChaCha20 extends \ParagonIE_Sodium_Core_ChaCha20
    {
    }

    class Curve25519 extends \ParagonIE_Sodium_Core_Curve25519
    {
    }

    class Ed25519 extends \ParagonIE_Sodium_Core_Ed25519
    {
    }

    class HChaCha20 extends \ParagonIE_Sodium_Core_HChaCha20
    {
    }

    class HSalsa20 extends \ParagonIE_Sodium_Core_HSalsa20
    {
    }

    class Poly1305 extends \ParagonIE_Sodium_Core_Poly1305
    {
    }

    class Salsa20 extends \ParagonIE_Sodium_Core_Salsa20
    {
    }

    class SipHash extends \ParagonIE_Sodium_Core_SipHash
    {
    }

    class Util extends \ParagonIE_Sodium_Core_Util
    {
    }

    class X25519 extends \ParagonIE_Sodium_Core_X25519
    {
    }

    class XChaCha20 extends \ParagonIE_Sodium_Core_XChaCha20
    {
    }

    class Xsalsa20 extends \ParagonIE_Sodium_Core_Xsalsa20
    {
    }
}

namespace ParagonIE\Sodium\Core\ChaCha20 {
    class Ctx extends \ParagonIE_Sodium_Core_ChaCha20_Ctx
    {
    }

    class IetfCtx extends \ParagonIE_Sodium_Core_ChaCha20_IetfCtx
    {
    }
}

namespace ParagonIE\Sodium\Core\Curve25519 {
    class Fe extends \ParagonIE_Sodium_Core_Curve25519_Fe
    {
    }

    class H extends \ParagonIE_Sodium_Core_Curve25519_H
    {
    }
}

namespace ParagonIE\Sodium\Core\Curve25519\Ge {
    class Cached extends \ParagonIE_Sodium_Core_Curve25519_Ge_Cached
    {
    }

    class P1p1 extends \ParagonIE_Sodium_Core_Curve25519_Ge_P1p1
    {
    }

    class P2 extends \ParagonIE_Sodium_Core_Curve25519_Ge_P2
    {
    }

    class P3 extends \ParagonIE_Sodium_Core_Curve25519_Ge_P3
    {
    }

    class Precomp extends \ParagonIE_Sodium_Core_Curve25519_Ge_Precomp
    {
    }
}

namespace ParagonIE\Sodium\Core\Poly1305 {
    class State extends \ParagonIE_Sodium_Core_Poly1305_State
    {
    }
}
