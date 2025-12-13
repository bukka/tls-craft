<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Exceptions\CryptoException;
use Php\TlsCraft\Exceptions\OpenSslException;

use const OPENSSL_KEYTYPE_X448;

class X448KeyExchange implements OpenSslKeyExchange
{
    public function generateKeyPair(): KeyPair
    {
        // Generate X448 key pair using OpenSSL
        $keyResource = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_X448,
        ]);

        if (!$keyResource) {
            throw new OpenSslException('Failed to generate X448 key pair');
        }

        // Get raw public key
        $details = openssl_pkey_get_details($keyResource);

        // For X448, the public key is in details['public_key_raw']
        $publicKey = $details['public_key_raw'] ?? null;

        if (!$publicKey) {
            // Fallback: extract from PEM if raw not available
            $publicKey = $this->extractRawFromPem($details['key'] ?? '');
        }

        if (!$publicKey || strlen($publicKey) !== 56) {
            throw new CryptoException('Failed to extract X448 public key');
        }

        return new OpenSslKeyPair($keyResource, $publicKey, $this);
    }

    public function getPeerPublicKey(string $peerPublicKey): mixed
    {
        if (strlen($peerPublicKey) !== 56) {
            throw new CryptoException('Invalid X448 peer public key length');
        }

        // Create peer public key in PEM format
        $peerPem = $this->createPublicKeyPem($peerPublicKey);

        $peerKeyResource = openssl_pkey_get_public($peerPem);
        if (!$peerKeyResource) {
            throw new OpenSslException('Failed to create peer public key resource');
        }

        return $peerKeyResource;
    }

    private function extractRawFromPem(string $pem): ?string
    {
        // Extract raw 56-byte public key from X448 PEM
        $der = base64_decode(str_replace(
            ['-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----', "\n", "\r"],
            '',
            $pem,
        ));

        if (!$der) {
            return null;
        }

        // X448 public key in DER is typically at the end, 56 bytes
        // This is a simplified extraction - proper ASN.1 parsing would be better
        $keyLen = 56;
        if (strlen($der) >= $keyLen) {
            return substr($der, -$keyLen);
        }

        return null;
    }

    private function createPublicKeyPem(string $rawPublicKey): string
    {
        // Create X448 public key in PEM format
        // This is the DER structure for X448 public key
        $oid = "\x30\x42\x30\x05\x06\x03\x2b\x65\x6f\x03\x39\x00";
        $der = $oid.$rawPublicKey;

        $pem = "-----BEGIN PUBLIC KEY-----\n";
        $pem .= chunk_split(base64_encode($der), 64);
        $pem .= "-----END PUBLIC KEY-----\n";

        return $pem;
    }
}
