<?php

require_once dirname(__FILE__) . '/Int64Test.php';

class Int64FastTest extends Int64Test
{
    public function setUp()
    {
        if (PHP_INT_SIZE === 8) {
            $this->markTestSkipped('Only relevant to 32-bit platforms.');
        } else {
            ParagonIE_Sodium_Compat::$fastMult = true;
        }
    }
}
