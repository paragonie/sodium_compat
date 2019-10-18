#!/usr/bin/env bash

sed -i "s/__DIR__/dirname(__FILE__)/g" vendor/*.php
sed -i "s/__DIR__/dirname(__FILE__)/g" vendor/composer/*.php
sed -i "s/autoload_real\.php/autoload_real_52\.php/g" vendor/autoload.php
