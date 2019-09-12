#!/usr/bin/env bash

basedir=$( dirname $( readlink -f ${BASH_SOURCE[0]} ) )

wget https://github.com/php/php-src/raw/PHP-7.3/ext/sodium/php_libsodium.h
echo "Checking files..."
sed -n -e 's#^PHP_FUNCTION(\(\S\+\));$#\1#p' php_libsodium.h | xargs -L1 php "${basedir}/polyfill_test.php"
STATUS="$?"
rm php_libsodium.h
echo "Check complete"
exit $STATUS
