<?php
require_once __DIR__ . '/vendor/autoload.php';

/**
 * @param string $class
 * @return bool
 */
function sodiumCompatAutoader($class)
{
    $namespace = 'ParagonIE_Sodium_';
    // does the class use the namespace prefix?
    $len = strlen($namespace);
    if (strncmp($namespace, $class, $len) !== 0) {
        // no, move to the next registered autoloader
        return false;
    }
    // get the relative class name
    $relative_class = substr($class, $len);
    // replace the namespace prefix with the base directory, replace namespace
    // separators with directory separators in the relative class name, append
    // with .php
    $file = __DIR__ . '/src/' . str_replace('_', '/', $relative_class) . '.php';
    // if the file exists, require it
    if (file_exists($file)) {
        require $file;
        return true;
    }
    return false;
}
spl_autoload_register('sodiumCompatAutoader');

if (PHP_VERSION_ID >= 50300) {
    // Namespaces didn't exist before 5.3.0, so don't even try to use this
    // unless PHP >= 5.3.0
    require_once __DIR__ . '/lib/sodium_compat.php';
}
