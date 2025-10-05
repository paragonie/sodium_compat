<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\Before;

/**
 * @coversNothing
 */
abstract class KnownAnswerTestCase extends TestCase
{
    #[Before]
    public function before(): void
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    protected function hextobin(string $hex): string
    {
        return ParagonIE_Sodium_Compat::hex2bin($hex);
    }
}
