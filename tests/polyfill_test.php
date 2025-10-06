<?php
require_once dirname(dirname(__FILE__)) . '/autoload.php';

if ($argc < 2) {
    echo 'No arguments passed!';
    var_dump($argv);
    exit(2);
}

$functionName = $argv[1];
$polyfill = str_replace('sodium_', '', $functionName);
if (str_contains($polyfill, 'crypto_core_ristretto')) {
    $polyfill = str_replace('crypto_core_', '', $polyfill);
}
if (str_contains($polyfill, 'crypto_scalarmult_ristretto25')) {
    $polyfill = str_replace('crypto_', '', $polyfill);
}

if (!method_exists('ParagonIE_Sodium_Compat', $polyfill)) {
    echo 'Polyfill not found for ', $functionName, ' (checked for ParagonIE_Sodium_Compat::', $polyfill, ')', PHP_EOL;
    exit(1);
}
exit(0);
