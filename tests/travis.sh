#!/usr/bin/env bash

vendor/bin/phpunit
EXITCOMMAND=$?
if [[ "$EXITCOMMAND" -ne 0 ]]; then exit $EXITCOMMAND; fi

vendor/bin/phpunit --bootstrap autoload-fast.php
EXITCOMMAND=$?
if [[ "$EXITCOMMAND" -ne 0 ]]; then exit $EXITCOMMAND; fi

if [[ $CHECK_MBSTRING -eq 1 ]]; then
  php -dmbstring.func_overload=7 vendor/bin/phpunit
  EXITCOMMAND=$?
  if [[ "$EXITCOMMAND" -ne 0 ]]; then exit $EXITCOMMAND; fi

  php -dmbstring.func_overload=7 vendor/bin/phpunit --bootstrap autoload-fast.php
  EXITCOMMAND=$?
  if [[ "$EXITCOMMAND" -ne 0 ]]; then exit $EXITCOMMAND; fi
fi
