<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Exceptions\CryptoException;

class EcdhKeyExchange implements KeyExchange
{
    public function __construct(private string $curveName) {}

    public function generateKeyPair(): KeyPair
    {
        $keyResource = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => $this->curveName
        ]);

        if (!$keyResource) {
            throw new CryptoException("Failed to generate ECDH key pair for {$this->curveName}");
        }

        $details = openssl_pkey_get_details($keyResource);
        return new OpenSslKeyPair(
            $keyResource,
            $details['ec']['pub'] ?? throw new CryptoException("Failed to extract public key")
        );
    }
}