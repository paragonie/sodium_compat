<?php

class ChaCha20Test extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @covers ParagonIE_Sodium_Core_ChaCha20::stream()
     * @covers ParagonIE_Sodium_Core_ChaCha20::streamXorIc()
     */
    public function testVectors()
    {
        $key = str_repeat("\x00", 32);
        $nonce = str_repeat("\x00", 8);
        if (PHP_INT_SIZE === 4) {
            $keystream = ParagonIE_Sodium_Core32_ChaCha20::stream(192, $nonce, $key);
        } else {
            $keystream = ParagonIE_Sodium_Core_ChaCha20::stream(192, $nonce, $key);
        }

        $block1 = ParagonIE_Sodium_Core_Util::substr($keystream, 0, 64);
        $block2 = ParagonIE_Sodium_Core_Util::substr($keystream, 64, 64);
        $block3 = ParagonIE_Sodium_Core_Util::substr($keystream, 128, 64);

        $this->assertSame(
            '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7'.
            'da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586',
            ParagonIE_Sodium_Core_Util::bin2hex($block1),
            'Test Vector #1 for ChaCha20 failed'
        );

        $this->assertSame(
            '9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed' .
            '29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f',
            ParagonIE_Sodium_Core_Util::bin2hex($block2),
            'Test Vector #2 for ChaCha20 failed'
        );

        $this->assertSame(
            '2d09a0e663266ce1ae7ed1081968a0758e718e997bd362c6b0c34634a9a0b35d' .
            '012737681f7b5d0f281e3afde458bc1e73d2d313c9cf94c05ff3716240a248f2',
            ParagonIE_Sodium_Core_Util::bin2hex($block3),
            'Test Vector #3 for ChaCha20 failed'
        );

        // Test with a key and nonce:
        $key = str_repeat("\x00", 31) . "\x01";
        $nonce = str_repeat("\x00", 7) . "\x02";
        if (PHP_INT_SIZE === 4) {
            $keystream = ParagonIE_Sodium_Core32_ChaCha20::stream(256, $nonce, $key);
        } else {
            $keystream = ParagonIE_Sodium_Core_ChaCha20::stream(256, $nonce, $key);
        }

        $block1 = ParagonIE_Sodium_Core_Util::substr($keystream, 0, 64);
        $block2 = ParagonIE_Sodium_Core_Util::substr($keystream, 64, 64);
        $block3 = ParagonIE_Sodium_Core_Util::substr($keystream, 128, 64);
        $block4 = ParagonIE_Sodium_Core_Util::substr($keystream, 192, 64);

        $this->assertSame(
            'ecfa254f845f647473d3cb140da9e87606cb33066c447b87bc2666dde3fbb739' .
            'a371c9ec7abcb4cfa9211f7d90f64c2d07f89e5cf9b93e330a6e4c08af5ba6d5',
            ParagonIE_Sodium_Core_Util::bin2hex($block1),
            'Test Vector #4 for ChaCha20 failed'
        );

        $this->assertSame(
            'e295895d808f4db326441fcb51ec53042e4029f72a6f1ef8d8b90c74250d3082' .
            '4ef2f0abb10b0961a096f37498bd047767fce3a228c5e3f9399211ba2bd44964',
            ParagonIE_Sodium_Core_Util::bin2hex($block2),
            'Test Vector #5 for ChaCha20 failed'
        );

        $this->assertSame(
            '2323944eea82cc9b386bd48486f02b7c00c689a97df8eec1e672416247172d16' .
            '62f4940316aac760606af75b7d87353c077645076ce5e464d9126d3fe9c78829',
            ParagonIE_Sodium_Core_Util::bin2hex($block3),
            'Test Vector #6 for ChaCha20 failed'
        );
        $this->assertSame(
            'a46ef02c80ea1ca4f60fca6143b1bd0f3623a1030d8c66c13f20c49743b65de9' .
            'e4ddb6ffd5e44cd87c8991d708059d41905c214287052fa7fe145ba7f7d68359',
            ParagonIE_Sodium_Core_Util::bin2hex($block4),
            'Test Vector #7 for ChaCha20 failed'
        );


        $key = ParagonIE_Sodium_Core_Util::hex2bin('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
        $nonce = ParagonIE_Sodium_Core_Util::hex2bin('0102030405060708');

        $message = str_repeat("\x00", 63) . "\xff";
        if (PHP_INT_SIZE === 4) {
            $block = ParagonIE_Sodium_Core32_ChaCha20::streamXorIc(
                $message,
                $nonce,
                $key,
                ParagonIE_Sodium_Core_Util::store64_le(0)
            );
        } else {
            $block = ParagonIE_Sodium_Core_ChaCha20::streamXorIc(
                $message,
                $nonce,
                $key,
                ParagonIE_Sodium_Core_Util::store64_le(0)
            );
        }
        $this->assertSame(
            '8cea583fc7886a36cbaffaa595edd2e3a0d76956217379cdc6eabcd330936f24' .
            'cc93ffa78f45908885cfa0eac4a5dd95726a1318f4471646d17af1d6b9b0b634',
            ParagonIE_Sodium_Core_Util::bin2hex($block),
            'Test Vector #8a for ChaCha20 failed -- key/nonce is likely broken'
        );
        $this->assertSame(
            '8cea583fc7886a36cbaffaa595edd2e3a0d76956217379cdc6eabcd330936f24' .
            'cc93ffa78f45908885cfa0eac4a5dd95726a1318f4471646d17af1d6b9b0b6cb',
            ParagonIE_Sodium_Core_Util::bin2hex(
                PHP_INT_SIZE === 4
                    ? ParagonIE_Sodium_Core32_ChaCha20::stream(64, $nonce, $key)
                    : ParagonIE_Sodium_Core_ChaCha20::stream(64, $nonce, $key)
            ),
            'Test Vector #8b for ChaCha20 failed -- key/nonce is likely broken'
        );

        if (PHP_INT_SIZE === 4) {
            $block = ParagonIE_Sodium_Core32_ChaCha20::streamXorIc(
                $message,
                $nonce,
                $key,
                ParagonIE_Sodium_Core_Util::store64_le(1)
            );
        } else {
            $block = ParagonIE_Sodium_Core_ChaCha20::streamXorIc(
                $message,
                $nonce,
                $key,
                ParagonIE_Sodium_Core_Util::store64_le(1)
            );
        }
        $this->assertSame(
            'efe6a5f8a58ca89c10bfe8d68aec275e958c64511c4d281c1bd534e26ce8a585' .
            '37100f8d6a6f568f7d19870eda79eeb24e809a7f6b1ef702c7843a7c1167d012',
            ParagonIE_Sodium_Core_Util::bin2hex($block),
            'Test Vector #8c for ChaCha20 failed -- counter is likely broken'
        );
        $this->assertSame(
            'efe6a5f8a58ca89c10bfe8d68aec275e958c64511c4d281c1bd534e26ce8a585' .
            '37100f8d6a6f568f7d19870eda79eeb24e809a7f6b1ef702c7843a7c1167d0ed',
            ParagonIE_Sodium_Core_Util::bin2hex(
                ParagonIE_Sodium_Core_Util::substr(
                    PHP_INT_SIZE === 4
                        ? ParagonIE_Sodium_Core32_ChaCha20::stream(128, $nonce, $key)
                        : ParagonIE_Sodium_Core_ChaCha20::stream(128, $nonce, $key),
                    64
                )
            ),
            'Test Vector #8d for ChaCha20 failed -- counter is likely broken'
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

        if (PHP_INT_SIZE === 4) {
            $ietfBlock = ParagonIE_Sodium_Core32_ChaCha20::streamXorIc(
                $message,
                $nonce,
                $key,
                ParagonIE_Sodium_Core_Util::store64_le(1)
            );
        } else {
            $ietfBlock = ParagonIE_Sodium_Core_ChaCha20::streamXorIc(
                $message,
                $nonce,
                $key,
                ParagonIE_Sodium_Core_Util::store64_le(1)
            );
        }

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
            'Test Vector #9 for ChaCha20 failed (long text) -- unknown issue'
        );
    }
}
