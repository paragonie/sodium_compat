<?php

/**
 * Class KeyConversionTest
 */
class KeyConversionTest extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @throws SodiumException
     * @throws TypeError
     */
    public function testPublicKeyConversion()
    {
        $sign_keypair = ParagonIE_Sodium_Compat::crypto_sign_keypair();
        $sign_secret  = ParagonIE_Sodium_Compat::crypto_sign_secretkey($sign_keypair);
        $sign_public  = ParagonIE_Sodium_Compat::crypto_sign_publickey($sign_keypair);

        $sk_convert = ParagonIE_Sodium_Compat::crypto_sign_ed25519_sk_to_curve25519($sign_secret);
        $pk_expect = ParagonIE_Sodium_Compat::crypto_box_publickey_from_secretkey($sk_convert);
        $pk_convert = ParagonIE_Sodium_Compat::crypto_sign_ed25519_pk_to_curve25519($sign_public);
        $this->assertSame(
            ParagonIE_Sodium_Core_Util::bin2hex($pk_expect),
            ParagonIE_Sodium_Core_Util::bin2hex($pk_convert),
            'Different strings from different approaches of converting Ed25519 -> X25519'
        );
        $messages = array(
            'test',
            str_repeat('A', 100),
            random_bytes(100)
        );

        foreach($messages as $message) {
            $sealed = ParagonIE_Sodium_Compat::crypto_box_seal($message, $pk_convert);
            $opened = ParagonIE_Sodium_Compat::crypto_box_seal_open($sealed, $sk_convert . $pk_convert);
            $this->assertSame($message, $opened);
            $opened = ParagonIE_Sodium_Compat::crypto_box_seal_open($sealed, $sk_convert . $pk_expect);
            $this->assertSame($message, $opened);
        }
    }
}
