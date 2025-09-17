<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Exceptions\CryptoException;

class X25519KeyExchange implements KeyExchange
{
    public function generateKeyPair(): KeyPair
    {
        $keyResource = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_X25519
        ]);

        if (!$keyResource) {
            throw new CryptoException("Failed to generate X25519 key pair");
        }

        $details = openssl_pkey_get_details($keyResource);
        return new OpenSSLKeyPair(
            $keyResource,
            $details['x25519']['pub'] ?? throw new CryptoException("Failed to extract X25519 public key")
        );
    }
}
