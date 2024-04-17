<?php
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__) . '/lib/php72compat.php';
if (!class_exists('PHPUnit_Framework_TestCase')) {
    class PHPUnit_Framework_TestCase extends TestCase {}
}
