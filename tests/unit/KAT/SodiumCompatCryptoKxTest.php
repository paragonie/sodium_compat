<?php

use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(ParagonIE_Sodium_Compat::class)]
class SodiumCompatCryptoKxTest extends KnownAnswerTestCase
{
    public function testCryptoKx(): void
    {
        $client_sk = ParagonIE_Sodium_Compat::crypto_kx_secretkey(
            $client_keypair = ParagonIE_Sodium_Compat::crypto_kx_keypair()
        );
        $client_pk = ParagonIE_Sodium_Compat::crypto_kx_publickey($client_keypair);

        $server_sk = ParagonIE_Sodium_Compat::crypto_kx_secretkey(
            $server_keypair = ParagonIE_Sodium_Compat::crypto_kx_keypair()
        );
        $server_pk = ParagonIE_Sodium_Compat::crypto_kx_publickey($server_keypair);

        list($rx_c, $tx_c) = ParagonIE_Sodium_Compat::crypto_kx_client_session_keys($client_keypair, $server_pk);
        list($rx_s, $tx_s) = ParagonIE_Sodium_Compat::crypto_kx_server_session_keys($server_keypair, $client_pk);

        $this->assertSame($rx_c, $tx_s);
        $this->assertSame($tx_c, $rx_s);
    }

    public function testCryptoKxSeed(): void
    {
        $seed = random_bytes(32);

        $client_keypair = ParagonIE_Sodium_Compat::crypto_kx_seed_keypair($seed);
        $client_pk = ParagonIE_Sodium_Compat::crypto_kx_publickey($client_keypair);

        $server_sk = ParagonIE_Sodium_Compat::crypto_kx_secretkey(
            $server_keypair = ParagonIE_Sodium_Compat::crypto_kx_keypair()
        );
        $server_pk = ParagonIE_Sodium_Compat::crypto_kx_publickey($server_keypair);

        list($rx_c, $tx_c) = ParagonIE_Sodium_Compat::crypto_kx_client_session_keys($client_keypair, $server_pk);
        list($rx_s, $tx_s) = ParagonIE_Sodium_Compat::crypto_kx_server_session_keys($server_keypair, $client_pk);

        $this->assertSame($rx_c, $tx_s);
        $this->assertSame($tx_c, $rx_s);
    }
}
