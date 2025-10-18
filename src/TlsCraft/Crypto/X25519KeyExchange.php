<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Exceptions\CryptoException;
use Php\TlsCraft\Exceptions\OpenSslException;

class X25519KeyExchange implements OpenSslKeyExchange
{
    public function generateKeyPair(): KeyPair
    {
        // Generate X25519 key pair using OpenSSL
        $keyResource = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_X25519,
        ]);

        if (!$keyResource) {
            throw new OpenSslException('Failed to generate X25519 key pair');
        }

        // Get raw public key
        $details = openssl_pkey_get_details($keyResource);

        // For X25519, the public key is in details['public_key_raw']
        $publicKey = $details['public_key_raw'] ?? null;

        if (!$publicKey) {
            // Fallback: extract from PEM if raw not available
            $publicKey = $this->extractRawFromPem($details['key'] ?? '');
        }

        if (!$publicKey || strlen($publicKey) !== 32) {
            throw new CryptoException('Failed to extract X25519 public key');
        }

        return new OpenSslKeyPair($keyResource, $publicKey, $this);
    }

    public function getPeerPublicKey(string $peerPublicKey): mixed
    {
        if (strlen($peerPublicKey) !== 32) {
            throw new CryptoException('Invalid X25519 peer public key length');
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
        // Extract raw 32-byte public key from X25519 PEM
        $der = base64_decode(str_replace(
            ['-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----', "\n", "\r"],
            '',
            $pem
        ));

        if (!$der) {
            return null;
        }

        // X25519 public key in DER is typically at the end, 32 bytes
        // This is a simplified extraction - proper ASN.1 parsing would be better
        $keyLen = 32;
        if (strlen($der) >= $keyLen) {
            return substr($der, -$keyLen);
        }

        return null;
    }

    private function createPublicKeyPem(string $rawPublicKey): string
    {
        // Create X25519 public key in PEM format
        // This is the DER structure for X25519 public key
        $oid = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x6e\x03\x21\x00";
        $der = $oid . $rawPublicKey;

        $pem = "-----BEGIN PUBLIC KEY-----\n";
        $pem .= chunk_split(base64_encode($der), 64);
        $pem .= "-----END PUBLIC KEY-----\n";

        return $pem;
    }
}
