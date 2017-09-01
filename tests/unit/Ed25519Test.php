<?php

class Ed25519Test extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * From RFC 8032 section 7.1
     *
     * @ref https://www.rfc-editor.org/rfc/rfc8032.txt
     * @covers ParagonIE_Sodium_Core_Ed25519::publickey_from_secretkey()
     * @covers ParagonIE_Sodium_Core_Ed25519::sign_detached()
     * @covers ParagonIE_Sodium_Core32_Ed25519::publickey_from_secretkey()
     * @covers ParagonIE_Sodium_Core32_Ed25519::sign_detached()
     */
    public function testVectorsRFC8032()
    {
        // TEST 1
        $secretKey = ParagonIE_Sodium_Core_Util::hex2bin(
            '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60' .
            'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
        );
        if (PHP_INT_SIZE === 4) {
            $publicKey = ParagonIE_Sodium_Core32_Ed25519::publickey_from_secretkey($secretKey);
        } else {
            $publicKey = ParagonIE_Sodium_Core_Ed25519::publickey_from_secretkey($secretKey);
        }

        $this->assertSame(
            'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
            bin2hex($publicKey),
            'RFC 8032 - Test #1 - Public Key'
        );
        if (PHP_INT_SIZE === 4) {
            $sig = ParagonIE_Sodium_Core32_Ed25519::sign_detached('', $secretKey);
        } else {
            $sig = ParagonIE_Sodium_Core_Ed25519::sign_detached('', $secretKey);
        }

        $this->assertSame(
            'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155' .
            '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
            bin2hex($sig),
            'RFC 8032 - Test #1 - Signature'
        );

        // TEST 2
        $secretKey = ParagonIE_Sodium_Core_Util::hex2bin(
            '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb' .
            '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'
        );
        if (PHP_INT_SIZE === 4) {
            $publicKey = ParagonIE_Sodium_Core32_Ed25519::publickey_from_secretkey($secretKey);
        } else {
            $publicKey = ParagonIE_Sodium_Core_Ed25519::publickey_from_secretkey($secretKey);
        }

        $this->assertSame(
            '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
            bin2hex($publicKey),
            'RFC 8032 - Test #2 - Public Key'
        );
        if (PHP_INT_SIZE === 4) {
            $sig = ParagonIE_Sodium_Core32_Ed25519::sign_detached('r', $secretKey);
        } else {
            $sig = ParagonIE_Sodium_Core_Ed25519::sign_detached('r', $secretKey);
        }

        $this->assertSame(
            '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da' .
            '085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
            bin2hex($sig),
            'RFC 8032 - Test #2 - Signature'
        );

        // TEST 3
        $secretKey = ParagonIE_Sodium_Core_Util::hex2bin(
            'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7' .
            'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025'
        );
        if (PHP_INT_SIZE === 4) {
            $publicKey = ParagonIE_Sodium_Core32_Ed25519::publickey_from_secretkey($secretKey);
        } else {
            $publicKey = ParagonIE_Sodium_Core_Ed25519::publickey_from_secretkey($secretKey);
        }

        $this->assertSame(
            'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
            bin2hex($publicKey),
            'RFC 8032 - Test #3 - Public Key'
        );
        if (PHP_INT_SIZE === 4) {
            $sig = ParagonIE_Sodium_Core32_Ed25519::sign_detached("\xaf\x82", $secretKey);
        } else {
            $sig = ParagonIE_Sodium_Core_Ed25519::sign_detached("\xaf\x82", $secretKey);
        }

        $this->assertSame(
            '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac' .
            '18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a',
            bin2hex($sig),
            'RFC 8032 - Test #3 - Signature'
        );

        // Test 1024
        $secretKey = ParagonIE_Sodium_Core_Util::hex2bin(
            'f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5' .
            '278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e'
        );
        if (PHP_INT_SIZE === 4) {
            $publicKey = ParagonIE_Sodium_Core32_Ed25519::publickey_from_secretkey($secretKey);
        } else {
            $publicKey = ParagonIE_Sodium_Core_Ed25519::publickey_from_secretkey($secretKey);
        }
        $this->assertSame(
            '278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e',
            bin2hex($publicKey),
            'RFC 8032 - Test 1024 - Public Key'
        );

        $message = ParagonIE_Sodium_Core_Util::hex2bin(
            '08b8b2b733424243760fe426a4b54908' .
            '632110a66c2f6591eabd3345e3e4eb98' .
            'fa6e264bf09efe12ee50f8f54e9f77b1' .
            'e355f6c50544e23fb1433ddf73be84d8' .
            '79de7c0046dc4996d9e773f4bc9efe57' .
            '38829adb26c81b37c93a1b270b20329d' .
            '658675fc6ea534e0810a4432826bf58c' .
            '941efb65d57a338bbd2e26640f89ffbc' .
            '1a858efcb8550ee3a5e1998bd177e93a' .
            '7363c344fe6b199ee5d02e82d522c4fe' .
            'ba15452f80288a821a579116ec6dad2b' .
            '3b310da903401aa62100ab5d1a36553e' .
            '06203b33890cc9b832f79ef80560ccb9' .
            'a39ce767967ed628c6ad573cb116dbef' .
            'efd75499da96bd68a8a97b928a8bbc10' .
            '3b6621fcde2beca1231d206be6cd9ec7' .
            'aff6f6c94fcd7204ed3455c68c83f4a4' .
            '1da4af2b74ef5c53f1d8ac70bdcb7ed1' .
            '85ce81bd84359d44254d95629e9855a9' .
            '4a7c1958d1f8ada5d0532ed8a5aa3fb2' .
            'd17ba70eb6248e594e1a2297acbbb39d' .
            '502f1a8c6eb6f1ce22b3de1a1f40cc24' .
            '554119a831a9aad6079cad88425de6bd' .
            'e1a9187ebb6092cf67bf2b13fd65f270' .
            '88d78b7e883c8759d2c4f5c65adb7553' .
            '878ad575f9fad878e80a0c9ba63bcbcc' .
            '2732e69485bbc9c90bfbd62481d9089b' .
            'eccf80cfe2df16a2cf65bd92dd597b07' .
            '07e0917af48bbb75fed413d238f5555a' .
            '7a569d80c3414a8d0859dc65a46128ba' .
            'b27af87a71314f318c782b23ebfe808b' .
            '82b0ce26401d2e22f04d83d1255dc51a' .
            'ddd3b75a2b1ae0784504df543af8969b' .
            'e3ea7082ff7fc9888c144da2af58429e' .
            'c96031dbcad3dad9af0dcbaaaf268cb8' .
            'fcffead94f3c7ca495e056a9b47acdb7' .
            '51fb73e666c6c655ade8297297d07ad1' .
            'ba5e43f1bca32301651339e22904cc8c' .
            '42f58c30c04aafdb038dda0847dd988d' .
            'cda6f3bfd15c4b4c4525004aa06eeff8' .
            'ca61783aacec57fb3d1f92b0fe2fd1a8' .
            '5f6724517b65e614ad6808d6f6ee34df' .
            'f7310fdc82aebfd904b01e1dc54b2927' .
            '094b2db68d6f903b68401adebf5a7e08' .
            'd78ff4ef5d63653a65040cf9bfd4aca7' .
            '984a74d37145986780fc0b16ac451649' .
            'de6188a7dbdf191f64b5fc5e2ab47b57' .
            'f7f7276cd419c17a3ca8e1b939ae49e4' .
            '88acba6b965610b5480109c8b17b80e1' .
            'b7b750dfc7598d5d5011fd2dcc5600a3' .
            '2ef5b52a1ecc820e308aa342721aac09' .
            '43bf6686b64b2579376504ccc493d97e' .
            '6aed3fb0f9cd71a43dd497f01f17c0e2' .
            'cb3797aa2a2f256656168e6c496afc5f' .
            'b93246f6b1116398a346f1a641f3b041' .
            'e989f7914f90cc2c7fff357876e506b5' .
            '0d334ba77c225bc307ba537152f3f161' .
            '0e4eafe595f6d9d90d11faa933a15ef1' .
            '369546868a7f3a45a96768d40fd9d034' .
            '12c091c6315cf4fde7cb68606937380d' .
            'b2eaaa707b4c4185c32eddcdd306705e' .
            '4dc1ffc872eeee475a64dfac86aba41c' .
            '0618983f8741c5ef68d3a101e8a3b8ca' .
            'c60c905c15fc910840b94c00a0b9d0'
        );
        $this->assertSame(
            1023,
            ParagonIE_Sodium_Core_Util::strlen($message)
        );

        if (PHP_INT_SIZE === 4) {
            $sig = ParagonIE_Sodium_Core32_Ed25519::sign_detached($message, $secretKey);
        } else {
            $sig = ParagonIE_Sodium_Core_Ed25519::sign_detached($message, $secretKey);
        }

        $this->assertSame(
            '0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350' .
            'aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03',
            bin2hex($sig),
            'RFC 8032 - Test 1024 - Signature'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Core_Ed25519::publickey_from_secretkey()
     * @covers ParagonIE_Sodium_Core_Ed25519::sign_detached()
     * @covers ParagonIE_Sodium_Core_Ed25519::verify_detached()
     * @covers ParagonIE_Sodium_Core32_Ed25519::publickey_from_secretkey()
     * @covers ParagonIE_Sodium_Core32_Ed25519::sign_detached()
     * @covers ParagonIE_Sodium_Core32_Ed25519::verify_detached()
     */
    public function testVectors()
    {
        $secretKey = ParagonIE_Sodium_Core_Util::hex2bin(
            'c4ffb94f252886b1378589af0d7d2004d9564b971ac73f09da827b80a5e39cd5' .
            'c50725d6a9b7df75a49f92accd3ab2cca4264a41d9c42cbd1e57eb2746e531d5'
        );
        if (PHP_INT_SIZE === 4) {
            $publicKey = ParagonIE_Sodium_Core32_Ed25519::publickey_from_secretkey($secretKey);
        } else {
            $publicKey = ParagonIE_Sodium_Core_Ed25519::publickey_from_secretkey($secretKey);
        }

        $this->assertSame(
            'c50725d6a9b7df75a49f92accd3ab2cca4264a41d9c42cbd1e57eb2746e531d5',
            bin2hex($publicKey)
        );

        $message = str_repeat("\x00", 128);
        if (PHP_INT_SIZE === 4) {
            $sig = ParagonIE_Sodium_Core32_Ed25519::sign_detached($message, $secretKey);
        } else {
            $sig = ParagonIE_Sodium_Core_Ed25519::sign_detached($message, $secretKey);
        }

        $this->assertSame(
            '8af8dee0f4e0396dac9f82078c6fff2587095fd2240543b6a723d603f47dfe72' .
            'cc7f315b0b666c5a68c736a0a0c3f0478fae1e73ae12ad6036ce0a9466f6b40e',
            bin2hex($sig),
            'Ed25519 signature'
        );
        
        if (PHP_INT_SIZE === 4) {
            $keypair = ParagonIE_Sodium_Core32_Ed25519::keypair();
            $secretKey = ParagonIE_Sodium_Core32_Ed25519::secretkey($keypair);
            $publicKey = ParagonIE_Sodium_Core32_Ed25519::publickey($keypair);
            $sig = ParagonIE_Sodium_Core32_Ed25519::sign_detached($message, $secretKey);

            $this->assertTrue(
                ParagonIE_Sodium_Core32_Ed25519::verify_detached($sig, $message, $publicKey),
                'Ed25519 signature verification'
            );
        } else {
            $keypair = ParagonIE_Sodium_Core_Ed25519::keypair();
            $secretKey = ParagonIE_Sodium_Core_Ed25519::secretkey($keypair);
            $publicKey = ParagonIE_Sodium_Core_Ed25519::publickey($keypair);
            $sig = ParagonIE_Sodium_Core_Ed25519::sign_detached($message, $secretKey);

            $this->assertTrue(
                ParagonIE_Sodium_Core_Ed25519::verify_detached($sig, $message, $publicKey),
                'Ed25519 signature verification'
            );
        }
    }
}
