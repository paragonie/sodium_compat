#!/usr/bin/env bash

rm -rf tests/compat # We don't need these.

vendor/bin/phpunit-php52
EXITCOMMAND=$?
if [[ "$EXITCOMMAND" -ne 0 ]]; then
  echo "PHPunit (first run) exited with return value $EXITCOMMAND."
  exit $EXITCOMMAND
fi

vendor/bin/phpunit-php52 --bootstrap autoload-fast.php
EXITCOMMAND=$?
if [[ "$EXITCOMMAND" -ne 0 ]]; then
  echo "PHPunit (second run) exited with return value $EXITCOMMAND."
  exit $EXITCOMMAND
fi

if [[ $CHECK_MBSTRING -eq 1 ]]; then
  php -dmbstring.func_overload=7 vendor/bin/phpunit-php52
  EXITCOMMAND=$?
  if [[ "$EXITCOMMAND" -ne 0 ]]; then
    echo "PHPunit (third run) exited with return value $EXITCOMMAND."
    exit $EXITCOMMAND
  fi
  php -dmbstring.func_overload=7 vendor/bin/phpunit-php52 --bootstrap autoload-fast.php
  EXITCOMMAND=$?
  if [[ "$EXITCOMMAND" -ne 0 ]]; then
    echo "PHPunit (fourth run) exited with return value $EXITCOMMAND."
    exit $EXITCOMMAND
  fi
fi
