<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Exceptions\CryptoException;

class ECDHKeyExchange
{
    public static function generateKeyPair(string $curve = 'prime256v1'): array
    {
        $config = [
            'curve_name' => $curve,
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ];

        $privateKey = openssl_pkey_new($config);
        if ($privateKey === false) {
            throw new CryptoException("Failed to generate ECDH key pair");
        }

        $details = openssl_pkey_get_details($privateKey);
        if ($details === false) {
            throw new CryptoException("Failed to get key details");
        }

        return [
            'private_key' => $privateKey,
            'public_key' => $details['key'],
            'public_key_point' => $details['ec']['point'] ?? null
        ];
    }

    public static function computeSharedSecret($privateKey, string $peerPublicKeyPoint): string
    {
        // Create a temporary public key resource from the peer's point
        $peerPublicKey = openssl_pkey_get_public([
            'ec' => ['curve_name' => 'prime256v1', 'point' => $peerPublicKeyPoint]
        ]);

        if ($peerPublicKey === false) {
            throw new CryptoException("Failed to create peer public key");
        }

        // Compute shared secret
        $sharedSecret = '';
        if (!openssl_dh_compute_key($peerPublicKeyPoint, $privateKey)) {
            throw new CryptoException("Failed to compute ECDH shared secret");
        }

        return $sharedSecret;
    }
}