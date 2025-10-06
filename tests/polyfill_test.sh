#!/usr/bin/env bash
set -e

if [[ $# -eq 0 ]]; then
  echo "USAGE: Pass the PHP major/minor version as the first argument:"
  echo "  polyfill_test.sh 8.3"
  exit 2
fi
PHP_VERSION="$1"
PHP_SRC_BRANCH=""

# Get the branch for the php-src repository
get_php_src_branch() {
    if [[ "${PHP_VERSION}" = "master" ]] || [[ "${PHP_VERSION}" = "main" ]]; then
        PHP_SRC_BRANCH="master"
        return
    fi
    PHP_SRC_BRANCH="PHP-${PHP_VERSION}"
}

# Download the php_libsodium.h file from the php-src repository
download_header() {
    local branch="$1"
    local url="https://github.com/php/php-src/raw/${branch}/ext/sodium/php_libsodium.h"
    echo "Downloading header from ${url}"
    wget -O php_libsodium.h "${url}"
    if [[ $? -ne 0 ]]; then
        echo "Failed to download header from ${url}"
        exit 1
    fi
}

basedir=$( dirname $( readlink -f ${BASH_SOURCE[0]} ) )
get_php_src_branch

STATUS=0
# Let's go
pushd "${basedir}"
    download_header "${PHP_SRC_BRANCH}"
    echo "Checking files..."
    # Allow this command to fail without exiting the script
    sed -n -e 's#^PHP_FUNCTION(\(\S\+\));$#\1#p' php_libsodium.h | xargs -L1 php "${basedir}/polyfill_test.php" || STATUS=$?
    rm php_libsodium.h
    echo "Check complete"
popd
exit $STATUS
