<?php

class XChaCha20Test extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

    /**
     * @covers ParagonIE_Sodium_Core_XChaCha20::stream()
     * @throws SodiumException
     * @throws TypeError
     */
    public function testVectors()
    {
        $tv = array(
            array("79c99798ac67300bbb2704c95c341e3245f3dcb21761b98e52ff45b24f304fc4", "b33ffd3096479bcfbc9aee49417688a0a2554f8d95389419", "c6e9758160083ac604ef90e712ce6e75d7797590744e0cf060f013739c"),
            array("79c99798ac67300bbb2704c95c341e3245f3dcb21761b98e52ff45b24f304fc5", "b33ffd3096479bcfbc9aee49417688a0a2554f8d95389419", "9ba886da62c0a7fc9a1a42b2cabb9a27ed8c9a8b1922de996ed6124545"),
            array("79c99798ac67300bbb2704c95c341e3245f3dcb21761b98e52ff45b24f304fc4", "b33ffd3096479bcfbc9aee49417688a0a2554f8d9538941a", "48f38baa2cd43d7900e1049968aa82da90bc16762589c9a17fac6b3023"),
            array("ddf7784fee099612c40700862189d0397fcc4cc4b3cc02b5456b3a97d1186173", "a9a04491e7bf00c3ca91ac7c2d38a777d88993a7047dfcc4", "2f289d371f6f0abc3cb60d11d9b7b29adf6bc5ad843e8493e928448d"),
            array("3d12800e7b014e88d68a73f0a95b04b435719936feba60473f02a9e61ae60682", "56bed2599eac99fb27ebf4ffcb770a64772dec4d5849ea2d", "a2c3c1406f33c054a92760a8e0666b84f84fa3a618f0"),
            array("5f5763ff9a30c95da5c9f2a8dfd7cc6efd9dfb431812c075aa3e4f32e04f53e4", "a5fa890efa3b9a034d377926ce0e08ee6d7faccaee41b771", "8a1a5ba898bdbcff602b1036e469a18a5e45789d0e8d9837d81a2388a52b0b6a0f51891528f424c4a7f492a8dd7bce8bac19fbdbe1fb379ac0"),
            array("eadc0e27f77113b5241f8ca9d6f9a5e7f09eee68d8a5cf30700563bf01060b4e", "a171a4ef3fde7c4794c5b86170dc5a099b478f1b852f7b64", "23839f61795c3cdbcee2c749a92543baeeea3cbb721402aa42e6cae140447575f2916c5d71108e3b13357eaf86f060cb"),
            array("91319c9545c7c804ba6b712e22294c386fe31c4ff3d278827637b959d3dbaab2", "410e854b2a911f174aaf1a56540fc3855851f41c65967a4e", "cbe7d24177119b7fdfa8b06ee04dade4256ba7d35ffda6b89f014e479faef6"),
            array("6a6d3f412fc86c4450fc31f89f64ed46baa3256ffcf8616e8c23a06c422842b6", "6b7773fce3c2546a5db4829f53a9165f41b08faae2fb72d5", "8b23e35b3cdd5f3f75525fc37960ec2b68918e8c046d8a832b9838f1546be662e54feb1203e2"),
            array("d45e56368ebc7ba9be7c55cfd2da0feb633c1d86cab67cd5627514fd20c2b391", "fd37da2db31e0c738754463edadc7dafb0833bd45da497fc", "47950efa8217e3dec437454bd6b6a80a287e2570f0a48b3fa1ea3eb868be3d486f6516606d85e5643becc473b370871ab9ef8e2a728f73b92bd98e6e26ea7c8ff96ec5a9e8de95e1eee9300c"),
            array("aface41a64a9a40cbc604d42bd363523bd762eb717f3e08fe2e0b4611eb4dcf3", "6906e0383b895ab9f1cf3803f42f27c79ad47b681c552c63", "a5fa7c0190792ee17675d52ad7570f1fb0892239c76d6e802c26b5b3544d13151e67513b8aaa1ac5af2d7fd0d5e4216964324838"),
            array("9d23bd4149cb979ccf3c5c94dd217e9808cb0e50cd0f67812235eaaf601d6232", "c047548266b7c370d33566a2425cbf30d82d1eaf5294109e", "a21209096594de8c5667b1d13ad93f744106d054df210e4782cd396fec692d3515a20bf351eec011a92c367888bc464c32f0807acd6c203a247e0db854148468e9f96bee4cf718d68d5f637cbd5a376457788e6fae90fc31097cfc"),
        );
        foreach ($tv as $idx => $t) {
            $key = ParagonIE_Sodium_Core_Util::hex2bin($t[0]);
            $nonce = ParagonIE_Sodium_Core_Util::hex2bin($t[1]);
            $expect = ParagonIE_Sodium_Core_Util::hex2bin($t[2]);
            $out_len = ParagonIE_Sodium_Core_Util::strlen($expect);

            if (PHP_INT_SIZE === 4) {
                $out = ParagonIE_Sodium_Core32_XChaCha20::stream($out_len, $nonce, $key);
            } else {
                $out = ParagonIE_Sodium_Core_XChaCha20::stream($out_len, $nonce, $key);
            }
            $this->assertSame(
                bin2hex($expect),
                bin2hex($out),
                'Test vector, round #' . $idx
            );
        }
    }

    /**
     * @covers ParagonIE_Sodium_Crypto::secretbox_xchacha20poly1305()
     * @throws SodiumException
     * @throws TypeError
     */
    public function testSecretbox()
    {
        $testVectors = array(
            array("065ff46a9dddb1ab047ee5914d6d575a828b8cc1f454b24e8cd0f57efdc49a34", "f83262646ce01293b9923a65a073df78c54b2e799cd6c4e5", "", "4c72340416339dcdea01b760db5adaf7"),
            array("d3c71d54e6b13506e07aa2e7b412a17a7a1f34df3d3148cd3f45b91ccaa5f4d9", "943b454a853aa514c63cf99b1e197bbb99da24b2e2d93e47", "76bd706e07741e713d90efdb34ad202067263f984942aae8bda159f30dfccc72200f8093520b85c5ad124ff7c8b2d920946e5cfff4b819abf84c7b35a6205ca72c9f8747c3044dd73fb4bebda1b476", "0384276f1cfa5c82c3e58f0f2acc1f821c6f526d2c19557cf8bd270fcde43fba1d88890663f7b2f5c6b1d7deccf5c91b4df5865dc55cc7e04d6793fc2db8f9e3b418f95cb796d67a7f3f7e097150cb607c435dacf82eac3d669866e5092ace"),
            array("9498fdb922e0596e32af7f8108def2068f5a32a5ac70bd33ade371701f3d98d0", "a0056f24be0d20106fe750e2ee3684d4457cbdcb3a74e566", "b1bc9cfedb340fb06a37eba80439189e48aa0cfd37020eec0afa09165af12864671b3fbddbbb20ac18f586f2f66d13b3ca40c9a7e21c4513a5d87a95319f8ca3c2151e2a1b8b86a35653e77f90b9e63d2a84be9b9603876a89d60fd708edcd64b41be1064b8ad1046553aaeb51dc70b8112c9915d94f2a5dad1e14e7009db6c703c843a4f64b77d44b179b9579ac497dac2d33", "4918790d46893fa3dca74d8abc57eef7fca2c6393d1beef5efa845ac20475db38d1a068debf4c5dbd8614eb072877c565dc52bd40941f0b590d2079a5028e426bf50bcbaadcbebf278bddceedc578a5e31379523dee15026ec82d34e56f2871fdf13255db199ac48f163d5ee7e4f4e09a39451356959d9242a39aea33990ab960a4c25346e3d9397fc5e7cb6266c2476411cd331f2bcb4486750c746947ec6401865d5"),
            array("fa2d915e044d0519248150e7c815b01f0f2a691c626f8d22c3ef61e7f16eea47", "c946065dc8befa9cc9f292ea2cf28f0256285565051792b7", "d5be1a24c7872115dc5c5b4234dbee35a6f89ae3a91b3e33d75249a0aecfed252341295f49296f7ee14d64de1ea6355cb8facd065052d869aeb1763cda7e418a7e33b6f7a81327181df6cd4de3a126d9df1b5e8b0b1a6b281e63f2", "6d32e3571afec58b0acabb54a287118b3ed6691f56cc8ead12d735352c9a050c2ca173c78b6092f9ad4b7c21c36fb0ce18560956395bab3099c54760a743051ac6a898a0b0034b5e953340c975cf7a873c56b27e66bca2bff1dd977addefc7935bb7550753dd13d1f1a43d"),
            array("6f149c2ec27af45176030c8dd7ab0e1e488f5803f26f75045d7a56f59a587a85", "952aff2f39bc70016f04ac7fb8b55fd22764ba16b56e255d", "8fde598c4bde5786abdc6ab83fce66d59782b6ce36afe028c447ad4086a748764afa88a520e837a9d56d0b7693b0476649f24c2aa44b94615a1efc75", "9bccf07974836fa4609d32d9527d928d184d9c6c0823af2f703e0e257a162d26d3678fa15ab1c4db76ac42084d32cefca8efaf77814c199b310999e327a3e3daa2e235b175979504ede87b58"),
            array("b964b7fdf442efbcc2cd3e4cd596035bdfb05ed7d44f7fd4dce2d5614af5c8c4", "2886fbfa4b35b68f28d31df6243a4fbc56475b69e24820a4", "", "b83fbdd112bf0f7d62eff96c9faa8850"),
            array("10c0ad4054b48d7d1de1d9ab6f782ca883d886573e9d18c1d47b6ee6b5208189", "977edf57428d0e0247a3c88c9a9ec321bbaae1a4da8353b5", "518e4a27949812424b2a381c3efea6055ee5e75eff", "0c801a037c2ed0500d6ef68e8d195eceb05a15f8edb68b35773e81ac2aca18e9be53416f9a"),
            array("7db0a81d01699c86f47a3ec76d46aa32660adad7f9ac72cf8396419f789f6bb1", "e7cb57132ce954e28f4470cca1dbda20b534cdf32fbe3658", "ee6511d403539e611ab312205f0c3b8f36a33d36f1dc44bb33d6836f0ab93b9f1747167bf0150f045fcd12a39479641d8bdde6fe01475196e8fe2c435e834e30a59f6aaa01ebcd", "ae8b1d4df4f982b2702626feca07590fedd0dfa7ae34e6a098372a1aa32f9fbf0ce2a88b5c16a571ef48f3c9fda689ce8ebb9947c9e2a28e01b1191efc81ad2ce0ed6e6fc7c164b1fc7f3d50b7f5e47a895db3c1fc46c0"),
            array("7b043dd27476cf5a2baf2907541d8241ecd8b97d38d08911737e69b0846732fb", "74706a2855f946ed600e9b453c1ac372520b6a76a3c48a76", "dbf165bb8352d6823991b99f3981ba9c8153635e5695477cba54e96a2a8c4dc5f9dbe817887d7340e3f48a", "ce57261afba90a9598de15481c43f26f7b8c8cb2806c7c977752dba898dc51b92a3f1a62ebf696747bfccf72e0edda97f2ccd6d496f55aefbb3ec2"),
            array("e588e418d658df1b2b1583122e26f74ca3506b425087bea895d81021168f8164", "4f4d0ffd699268cd841ce4f603fe0cd27b8069fcf8215fbb", "f91bcdcf4d08ba8598407ba8ef661e66c59ca9d89f3c0a3542e47246c777091e4864e63e1e3911dc01257255e551527a53a34481be", "22dc88de7cacd4d9ce73359f7d6e16e74caeaa7b0d1ef2bb10fda4e79c3d5a9aa04b8b03575fd27bc970c9ed0dc80346162469e0547030ddccb8cdc95981400907c87c9442")
        );
        foreach ($testVectors as $idx => $test) {
            $key = ParagonIE_Sodium_Core_Util::hex2bin($test[0]);
            $nonce = ParagonIE_Sodium_Core_Util::hex2bin($test[1]);
            $message = ParagonIE_Sodium_Core_Util::hex2bin($test[2]);
            $expect = ParagonIE_Sodium_Core_Util::hex2bin($test[3]);

            if (PHP_INT_SIZE === 4) {
                $out = ParagonIE_Sodium_Crypto32::secretbox_xchacha20poly1305(
                    $message,
                    $nonce,
                    $key
                );
            } else {
                $out = ParagonIE_Sodium_Crypto::secretbox_xchacha20poly1305(
                    $message,
                    $nonce,
                    $key
                );
            }
            $this->assertSame(
                bin2hex($expect),
                bin2hex($out),
                'Test vector, round #' . $idx
            );
        }
    }

    /**
     * @throws SodiumException
     */
    public function testLibsodiumVectors()
    {
        $testVectors = array(
            array("79c99798ac67300bbb2704c95c341e3245f3dcb21761b98e52ff45b24f304fc4", "b33ffd3096479bcfbc9aee49417688a0a2554f8d95389419", "c6e9758160083ac604ef90e712ce6e75d7797590744e0cf060f013739c"),
            array("ddf7784fee099612c40700862189d0397fcc4cc4b3cc02b5456b3a97d1186173", "a9a04491e7bf00c3ca91ac7c2d38a777d88993a7047dfcc4", "2f289d371f6f0abc3cb60d11d9b7b29adf6bc5ad843e8493e928448d"),
            array("3d12800e7b014e88d68a73f0a95b04b435719936feba60473f02a9e61ae60682", "56bed2599eac99fb27ebf4ffcb770a64772dec4d5849ea2d", "a2c3c1406f33c054a92760a8e0666b84f84fa3a618f0"),
            array("5f5763ff9a30c95da5c9f2a8dfd7cc6efd9dfb431812c075aa3e4f32e04f53e4", "a5fa890efa3b9a034d377926ce0e08ee6d7faccaee41b771", "8a1a5ba898bdbcff602b1036e469a18a5e45789d0e8d9837d81a2388a52b0b6a0f51891528f424c4a7f492a8dd7bce8bac19fbdbe1fb379ac0"),
            array("eadc0e27f77113b5241f8ca9d6f9a5e7f09eee68d8a5cf30700563bf01060b4e", "a171a4ef3fde7c4794c5b86170dc5a099b478f1b852f7b64", "23839f61795c3cdbcee2c749a92543baeeea3cbb721402aa42e6cae140447575f2916c5d71108e3b13357eaf86f060cb"),
            array("91319c9545c7c804ba6b712e22294c386fe31c4ff3d278827637b959d3dbaab2", "410e854b2a911f174aaf1a56540fc3855851f41c65967a4e", "cbe7d24177119b7fdfa8b06ee04dade4256ba7d35ffda6b89f014e479faef6"),
            array("6a6d3f412fc86c4450fc31f89f64ed46baa3256ffcf8616e8c23a06c422842b6", "6b7773fce3c2546a5db4829f53a9165f41b08faae2fb72d5", "8b23e35b3cdd5f3f75525fc37960ec2b68918e8c046d8a832b9838f1546be662e54feb1203e2"),
            array("d45e56368ebc7ba9be7c55cfd2da0feb633c1d86cab67cd5627514fd20c2b391", "fd37da2db31e0c738754463edadc7dafb0833bd45da497fc", "47950efa8217e3dec437454bd6b6a80a287e2570f0a48b3fa1ea3eb868be3d486f6516606d85e5643becc473b370871ab9ef8e2a728f73b92bd98e6e26ea7c8ff96ec5a9e8de95e1eee9300c"),
            array("aface41a64a9a40cbc604d42bd363523bd762eb717f3e08fe2e0b4611eb4dcf3", "6906e0383b895ab9f1cf3803f42f27c79ad47b681c552c63", "a5fa7c0190792ee17675d52ad7570f1fb0892239c76d6e802c26b5b3544d13151e67513b8aaa1ac5af2d7fd0d5e4216964324838"),
            array("9d23bd4149cb979ccf3c5c94dd217e9808cb0e50cd0f67812235eaaf601d6232", "c047548266b7c370d33566a2425cbf30d82d1eaf5294109e", "a21209096594de8c5667b1d13ad93f744106d054df210e4782cd396fec692d3515a20bf351eec011a92c367888bc464c32f0807acd6c203a247e0db854148468e9f96bee4cf718d68d5f637cbd5a376457788e6fae90fc31097cfc"),
        );
        foreach ($testVectors as $vector) {
            list($key, $nonce, $out) = $vector;
            $key = ParagonIE_Sodium_Core_Util::hex2bin($key);
            $nonce = ParagonIE_Sodium_Core_Util::hex2bin($nonce);
            $out = ParagonIE_Sodium_Core_Util::hex2bin($out);
            $m = str_repeat("\0", ParagonIE_Sodium_Core_Util::strlen($out));

            if (PHP_INT_SIZE === 4) {
                $calc = ParagonIE_Sodium_Core32_XChaCha20::ietfStreamXorIc(
                    $m,
                    $nonce,
                    $key,
                    "\x00\x00\x00\x00\x00\x00\x00\x00"
                );
            } else {
                $calc = ParagonIE_Sodium_Core_XChaCha20::ietfStreamXorIc(
                    $m,
                    $nonce,
                    $key,
                    "\x00\x00\x00\x00\x00\x00\x00\x00"
                );
            }
            $this->assertSame(
                ParagonIE_Sodium_Core_Util::bin2hex($out),
                ParagonIE_Sodium_Core_Util::bin2hex($calc),
                'Libsodium test vector failed'
            );
        }
    }
}
