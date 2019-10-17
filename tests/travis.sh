#!/usr/bin/env bash

vendor/bin/phpunit
vendor/bin/phpunit --bootstrap autoload-fast.php
if [[ $CHECK_MBSTRING -eq 1 ]]; then
  php -dmbstring.func_overload=7 vendor/bin/phpunit
  php -dmbstring.func_overload=7 vendor/bin/phpunit --bootstrap autoload-fast.php
fi
