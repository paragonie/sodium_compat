<?php
require_once dirname(dirname(__FILE__)) . '/autoload.php';
$polyfill = str_replace('sodium_', '', $argv[1]);
if (!method_exists('ParagonIE_Sodium_Compat', $polyfill)) {
    echo $polyfill, ': NOT FOUND', PHP_EOL;
    exit(1);
} else {
    // echo $polyfill, ': FOUND', PHP_EOL;
}
