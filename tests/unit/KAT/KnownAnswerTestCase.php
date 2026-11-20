<?php

/**
 * @coversNothing
 */
abstract class KnownAnswerTestCase extends PHPUnit_Framework_TestCase
{
    /**
     * @before
     */
    public function before()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    protected function hextobin($hex)
    {
        return ParagonIE_Sodium_Compat::hex2bin($hex);
    }
}
