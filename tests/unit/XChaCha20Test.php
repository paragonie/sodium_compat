<?php

class XChaCha20Test extends PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
    }

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

            $out = ParagonIE_Sodium_Core_XChaCha20::stream($out_len, $nonce, $key);
            $this->assertSame(
                bin2hex($expect),
                bin2hex($out),
                'Test vector, round #' . $idx
            );
        }
    }
}
