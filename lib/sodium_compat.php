<?php
namespace Sodium;

/* If the PHP extension is installed, don't do anything
 */
if (!extension_loaded('libsodium')) {
    if (!is_callable('\\Sodium\\bin2hex')) {
        function bin2hex()
        {
            return call_user_func_array(
                array('ParagonIE_Sodium_Compat', 'bin2hex'),
                func_get_args()
            );
        }
    }
    if (!is_callable('\\Sodium\\compare')) {
        function compare()
        {
            return call_user_func_array(
                array('ParagonIE_Sodium_Compat', 'compare'),
                func_get_args()
            );
        }
    }
    if (!is_callable('\\Sodium\\hex2bin')) {
        function hex2bin()
        {
            return call_user_func_array(
                array('ParagonIE_Sodium_Compat', 'hex2bin'),
                func_get_args()
            );
        }
    }
}
