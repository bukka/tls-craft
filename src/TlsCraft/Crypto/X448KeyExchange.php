<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Exceptions\CryptoException;

class X448KeyExchange implements KeyExchange
{
    public function generateKeyPair(): KeyPair
    {
        $keyResource = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_X448
        ]);

        if (!$keyResource) {
            throw new CryptoException("Failed to generate X448 key pair");
        }

        $details = openssl_pkey_get_details($keyResource);
        return new OpenSSLKeyPair(
            $keyResource,
            $details['x448']['pub'] ?? throw new CryptoException("Failed to extract X448 public key")
        );
    }
}
