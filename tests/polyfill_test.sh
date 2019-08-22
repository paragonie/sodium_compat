#!/usr/env/bin bash
wget https://github.com/php/php-src/raw/PHP-7.3/ext/sodium/php_libsodium.h
sed -n -e 's#^PHP_FUNCTION(\(\S\+\));$#\1#p' php_libsodium.h | xargs -L1 php polyfill_test.php
rm php_libsodium.h
