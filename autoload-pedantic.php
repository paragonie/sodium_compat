<?php

require_once dirname(__FILE__) . '/autoload.php';
define('DO_PEDANTIC_TEST', true);

ParagonIE_Sodium_Compat::$fastMult = true;
