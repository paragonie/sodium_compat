<?php

class ChaCha20Test extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    public function testVectors()
    {
        $key = str_repeat("\x00", 32);
        $nonce = str_repeat("\x00", 8);

        $keystream = ParagonIE_Sodium_Core_ChaCha20::stream(192, $nonce, $key);

        $block1 = ParagonIE_Sodium_Core_Util::substr($keystream, 0, 64);
        $block2 = ParagonIE_Sodium_Core_Util::substr($keystream, 64, 64);
        $block3 = ParagonIE_Sodium_Core_Util::substr($keystream, 128, 64);

        $this->assertSame(
            '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7'.
            'da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586',
            ParagonIE_Sodium_Core_Util::bin2hex($block1),
            'Test Vector #1 forChaCha20 failed'
        );

        $this->assertSame(
            '9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed' .
            '29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f',
            ParagonIE_Sodium_Core_Util::bin2hex($block2),
            'Test Vector #2 forChaCha20 failed'
        );

        $this->assertSame(
            '2d09a0e663266ce1ae7ed1081968a0758e718e997bd362c6b0c34634a9a0b35d' .
            '012737681f7b5d0f281e3afde458bc1e73d2d313c9cf94c05ff3716240a248f2',
            ParagonIE_Sodium_Core_Util::bin2hex($block3),
            'Test Vector #3 forChaCha20 failed'
        );


        $message = 'Any submission t' .
                   'o the IETF inten' .
                   'ded by the Contr' .
                   'ibutor for publi' .
                   'cation as all or' .
                   ' part of an IETF' .
                   ' Internet-Draft ' .
                   'or RFC and any s' .
                   'tatement made wi' .
                   'thin the context' .
                   ' of an IETF acti' .
                   'vity is consider' .
                   'ed an "IETF Cont' .
                   'ribution". Such ' .
                   'statements inclu' .
                   'de oral statemen' .
                   'ts in IETF sessi' .
                   'ons, as well as ' .
                   'written and elec' .
                   'tronic communica' .
                   'tions made at an' .
                   'y time or place,' .
                   ' which are addre' .
                   'ssed to';
        $key = str_repeat("\x00", 31) . "\x01";
        $nonce = str_repeat("\x00", 7) . "\x02";

        $ietfBlock = ParagonIE_Sodium_Core_ChaCha20::streamXorIc(
            $message,
            $nonce,
            $key,
            ParagonIE_Sodium_Core_Util::store64_le(1)
        );

        $this->assertSame(
            'a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec' .
            '2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d' .
            '4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e527950' .
            '42bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85a' .
            'd00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259d' .
            'c4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b' .
            '0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6c' .
            'cc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0b' .
            'c39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f' .
            '5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e6' .
            '98ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab' .
            '7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221',
            ParagonIE_Sodium_Core_Util::bin2hex($ietfBlock),
            'Test Vector #3 forChaCha20 failed'
        );
    }
}
