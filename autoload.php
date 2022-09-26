<?php
require_once dirname(__FILE__) . '/autoload-php7.php';
/* Explicitly, always load the Compat class: */
if (!class_exists('ParagonIE_Sodium_Compat', false)) {
    require_once dirname(__FILE__) . '/src/Compat.php';
}

if (!class_exists('SodiumException', false)) {
    require_once dirname(__FILE__) . '/src/SodiumException.php';
}
require_once dirname(__FILE__) . '/lib/namespaced.php';
require_once dirname(__FILE__) . '/lib/sodium_compat.php';
if (!extension_loaded('sodium')) {
    if (!defined('SODIUM_CRYPTO_SCALARMULT_BYTES')) {
        require_once dirname(__FILE__) . '/lib/php72compat_const.php';
    }
    assert(class_exists('ParagonIE_Sodium_Compat'), 'Possible filesystem/autoloader bug?');
    require_once(dirname(__FILE__) . '/lib/php72compat.php');
} elseif (!function_exists('sodium_crypto_stream_xchacha20_xor')) {
    // Older versions of {PHP, ext/sodium} will not define these
    require_once(dirname(__FILE__) . '/lib/php72compat.php');
}
require_once(dirname(__FILE__) . '/lib/stream-xchacha20.php');
require_once(dirname(__FILE__) . '/lib/ristretto255.php');
