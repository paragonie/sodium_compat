<?php

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\BeforeClass;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class CompareTest extends TestCase
{
    #[BeforeClass]
    public function before(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Compat tests require ext-sodium');
        }
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @throws SodiumException
     */
    public function testCompare(): void
    {
        $this->assertSame(
            sodium_compare('foo', 'foo'),
            ParagonIE_Sodium_Compat::compare('foo', 'foo')
        );
        $this->assertSame(
            sodium_compare('foo', 'bar'),
            ParagonIE_Sodium_Compat::compare('foo', 'bar')
        );
        $this->assertSame(
            sodium_compare('bar', 'foo'),
            ParagonIE_Sodium_Compat::compare('bar', 'foo')
        );
        $this->assertSame(
            sodium_compare("foo\0\0\0", 'foobar'),
            ParagonIE_Sodium_Compat::compare("foo\0\0\0", 'foobar')
        );
        $this->assertSame(
            sodium_compare('foobar', "foo\0\0\0"),
            ParagonIE_Sodium_Compat::compare('foobar', "foo\0\0\0")
        );
    }
}
