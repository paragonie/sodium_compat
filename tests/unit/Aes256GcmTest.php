<?php

if (PHP_VERSION_ID >= 70000 && !class_exists('PHPUnit_Framework_TestCase')) {
    require_once dirname(dirname(dirname(__FILE__))) . '/autoload-phpunit.php';
}

class Aes256GcmTest extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_is_available()
     */
    public function testIsAvailable()
    {
        $this->assertTrue(
            is_bool(
                ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_is_available()
            ),
            'crypto_aead_aes256gcm_is_available() is not returning a boolean value'
        );
    }

    /**
     * @covers ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_decrypt()
     * @covers ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_encrypt()
     */
    public function testAes256Gcm()
    {
        if (!ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_is_available()) {
            $this->markTestSkipped('Cannot test AES-256-GCM; it is not available.');
            return;
        }
        $testCases = array(
            array(
                'key' =>
                    ParagonIE_Sodium_Core_Util::hex2bin(
                        'efb9de8bf561f4f7684b28b7ba5e7604948d3f25c44fc454f2ccfbcc975a542e'
                    ),
                'msg' =>
                    ParagonIE_Sodium_Core_Util::hex2bin(
                        '70617261676f6e69652f736f6469756d5f636f6d7061742076312e342b20756e6974207465737469' .
                        '6e67'
                    ),
                'nonce' =>
                    hex2bin(
                        '2e3db4c16506b4125917306c'
                    ),
                'aad' =>
                    hex2bin(
                        '50617261676f6e20496e697469617469766520456e7465727072697365732c204c4c43'
                    ),
                'ciphertext' =>
                    hex2bin(
                        'b6f5cca4aca4663ed79d24ab6253fb68e11228952d065e49406301cb2efffb25fca808fd069d9e3e' .
                        '7cf9bf8f208b4a4c3fd3eead5462bca0cae0'
                    )
            ),
            array(
                'key' =>
                    ParagonIE_Sodium_Core_Util::hex2bin(
                        'ce700f44c94e9e6be34c5a6dbdcc2ef38b079c732a391b2964d9da77a33d3be4'
                    ),
                'msg' =>
                    ParagonIE_Sodium_Core_Util::hex2bin(
                        'd961650d4d268babcddee555fbda0dc84adb2f6b05ad3d5384bc1d7c41f618ec9894874818dbcab9' .
                        '874539064226bb9fa318c0a3ae61b6e10d00ed4f32b55e36fee7d1434177e7841f1fff63c8b8fbfc' .
                        '4c6fe626a7c91bd32eaeedd860657043c387eb62c31e5c0f40b35f37ce909aa69a569c6cdd005e7f' .
                        '7643786aa2334470a0258efe1bcfcaadf9056f1c65626e8e94c7d62e23e9c2459c73d7eec11a01e4' .
                        '452b54ee46cd42866b1f5bdaaa81b62726cab1b757d2acb9f1c069168b4b1283af3ae5a5929b9715' .
                        '46945fc70c0d47edb4a45d3f1af31c2c095459834962dfe4f56023ffabf5075b99a7e9f134812514' .
                        'fa397167c67b7e81eee471f9f7f6977ab58430a83a543732a54c31b7466bc3ca66346cdd53828cc4' .
                        'aef44702ad24fab5b912f29b3f23e8d943be3bd09b212364de86127f446b6599c214d85e59420e98' .
                        'badea3f27108a739982432adc3e7f69522d2a4a7e0ff952e51e68c0125a0ab3801bbfa09700befb3' .
                        '60befe416d747fa2cda1bc8eaf0a369a28d67ce750e73d1dde4ea358f5d66fa8ef37ad6fa2da829b' .
                        '6aa477f4f40198f06262afffcd8a4e11a6e25a3c60c1bba8f1e4ca924da5f201e733261230f43be3' .
                        'af65d70d4d903ac12af7ae06d66cc57124f32eef667cf63f5dd8531452a240fe63ca825964333122' .
                        'd3249fe8671e3d8caed5fb69fe476da2ccaa78356a97966a141f520a43427d3a9ebf027ef54af43f' .
                        '1d29f15922b41628d7f459a3a1600f09c4e6bd'),
                'nonce' =>
                    hex2bin(
                        '950b27dc2df7d73b37bffd19'
                    ),
                'aad' =>
                    hex2bin(
                        'a4b50d28deb5ae802a69a978c1f9f91958eee746c29691c3b41eb189a25838720a50e2e9741ac925' .
                        '591d4ae7c32252c4b8266151f6bc626eb9fb3c3ae11642036da41c8a417d013b6905e4ff5714e052' .
                        '56805beee38cce7b874238507b7cccc1b512857f7258a11c399dbd69c3a7bc2229c3b6122b58d430' .
                        'c35eb5f5f36136556dcd6700dc6827d8e130a0f578b27b7522e1d19c9b014aae5c10ed3ee3771caa' .
                        '72c1b0015681168b0f4ba424625fa4884f8f31e11e841ea74a84cc418f044071726f34e122d4dcce' .
                        'ab91ff513b913f32d7c9794e42be1f9c5c6bd29c74c9e00140034b233021bd6c13b93ff9a471244b' .
                        '0f7e998541746a75f5a2b966c8fd3378131a4918f8d9ae1ac6b5cd2fc67acdf500b8f938b501feaf' .
                        'bac86db961ccbd8fa9d7a39df01fdc024f6820853f75bfa569dfb95e89062af5f8f2348f001dabe5' .
                        '293f279ef9721f2634557c07a96d52455af7dc501aa6532f572ccb7868ae247558dac5511dd7f428' .
                        '83ce8afc61cde87aeea6fa0b89f0291f58e6f7bd17ba8c24c8e953b0bfc20334195ad08cc9621499' .
                        '98596bf48ee9a067ecb02fce4f16233a9b8bb43a626b64088336915f8830dd6d136a35bef02f8560' .
                        '0e1c51f88e26537a2d90bfbd0fcd495acd3cd34c5ecc0d5ff52dbdc0460e958c092f6e18163e4e30' .
                        '3f31331e1a9380e45c4bafeb8c96a2efd33d55632ea598d6647083c677d86547ad1718fb48bf059b' .
                        '09819c7366073713d60c40d8b8bfa69a119509ce1f1fd9b788c1c77aad92102a44d5421bdef357c4' .
                        '66a58b5f541f401d0676b3fcc20c0b7076ee7d8c3f63831fcdbb0df23cfe989c13e8ff88bb9a35a7' .
                        '0e74780bc8f4a48a4251308abf1f4c40d64bb4bb25852a2032e97316fbc7ca1956e479791bf7a56a' .
                        'd100cffdd9df6845e9fad3e606a154961b4f27f355c1818f'
                    ),
                'ciphertext' =>
                    hex2bin(
                        '7372a7bebb82dc132e8c5307a0c95d22978aa9483f88d2ed01cab5101ad6d123cbcf8471952f2032' .
                        '4494f7c75f66bc9f13dd284bdfe5d8dce09afb1ab678759cab87cff48be23529f8d7d1f5ea5bff2e' .
                        '20674c884bcadd9ac8d195607e672d28dc26be670ac43dfa0f31bc9457d640f45f0a60d1f7aecad9' .
                        'db62c923366467e9a86732bc207f55bd4df6f63a44f0a400a5d51659eaba86ca23159c9d6d553309' .
                        '2d3c801665853bc849c3abe59f6af69c7a2a6eb0c298a7990dd7aeb2f0d1913164936136160aeb7d' .
                        '8e068ec7870df65d8091c0baf71c8bd3d8de02fc5dd3899209b5a7b8c1d801e8a1f39706aad5e928' .
                        'f717da35e3a309bec7533940498eb971a22128011dc5d9748bd9045275fc3031eaca971cc43a0673' .
                        'bc4e1683cfc84e776ddddb328b902d27a21fa6dc824d28bcf9dc6a01a1a460de4281455cd39b02f4' .
                        '8a7a1bd07bbcbd800924da7f91440d9d8c066fe22601e1dbda5f56e5fa31af032d3cd3665632b0a6' .
                        '2cf43fd171e6678ca60b3eff4445a9e68d88440c7b84eed16a76caf2fc4bddfa4f3ea56a87a5a080' .
                        'f0f7f2941dad25afac9d2308f4a39278bab39a83c999f39ddf1c4b53b5c5bfff8f3e96117a5e1b0a' .
                        '83f0ac27ebe4ba71332bbadd3c5132f316e6a0b3a438c1cc1b96bf9ff97210106657e35ed7f0e04f' .
                        '1f3fd2b2443e20e42bd4684f6e0da4917153ded48f99f4615a502cd160599cb9173afa5280a60d62' .
                        'fd7131bf667c8c8d9e631de8d29b98ce6b1ea24ff5098597dea729b05ac18f74e2ec34'
                    )
            )
        );
        foreach ($testCases as $case) {
            $encrypted = ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_encrypt(
                $case['msg'],
                $case['aad'],
                $case['nonce'],
                $case['key']
            );
            $this->assertSame(
                ParagonIE_Sodium_Core_Util::bin2hex($case['ciphertext']),
                ParagonIE_Sodium_Core_Util::bin2hex($encrypted)
            );
            $decrypted = ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_decrypt(
                $encrypted,
                $case['aad'],
                $case['nonce'],
                $case['key']
            );
            $this->assertSame(
                $case['msg'],
                $decrypted
            );
            $this->assertFalse(
                ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_decrypt(
                    $encrypted,
                    'x' . $case['aad'],
                    $case['nonce'],
                    $case['key']
                )
            );
            try {
                ParagonIE_Sodium_Compat::crypto_aead_aes256gcm_decrypt(
                    $encrypted,
                    $case['nonce'],
                    $case['aad'],
                    $case['key']
                );
                $this->fail('Exception not raised');
            } catch (SodiumException $ex) {

            }
        }
    }
}
