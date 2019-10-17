#!/usr/bin/env bash

php php52-phpunit.phar
php php52-phpunit.phar --bootstrap autoload-fast.php
if [[ $CHECK_MBSTRING -eq 1 ]]; then
  php -dmbstring.func_overload=7 php52-phpunit.phar
  php -dmbstring.func_overload=7 php52-phpunit.phar --bootstrap autoload-fast.php
fi
