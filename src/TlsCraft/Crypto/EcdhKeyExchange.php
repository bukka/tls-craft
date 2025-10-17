<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Exceptions\CryptoException;

use const OPENSSL_KEYTYPE_EC;

class EcdhKeyExchange implements OpenSslKeyExchange
{
    private const CURVE_MAPPING = [
        'secp256r1' => 'prime256v1',  // P-256
        'secp384r1' => 'secp384r1',   // P-384 (same name in OpenSSL)
        'secp521r1' => 'secp521r1',   // P-521 (same name in OpenSSL)
    ];

    private string $opensslCurveName;

    public function __construct(private string $curveName)
    {
        $this->opensslCurveName = self::CURVE_MAPPING[$curveName]
            ?? throw new CryptoException("Unsupported curve: {$curveName}");
    }

    public function generateKeyPair(): KeyPair
    {
        $keyResource = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => $this->opensslCurveName,
        ]);

        if (!$keyResource) {
            throw new CryptoException("Failed to generate ECDH key pair for {$this->curveName} (OpenSSL: {$this->opensslCurveName})");
        }

        $details = openssl_pkey_get_details($keyResource);

        // Extract x and y coordinates from the details
        $x = $details['ec']['x'] ?? null;
        $y = $details['ec']['y'] ?? null;

        if (!$x || !$y) {
            throw new CryptoException('Failed to extract EC point coordinates');
        }

        // Determine the expected coordinate length for this curve
        $coordLen = $this->getCoordinateLength();

        // Pad coordinates to the correct length if necessary (important for P-521)
        $x = str_pad($x, $coordLen, "\x00", STR_PAD_LEFT);
        $y = str_pad($y, $coordLen, "\x00", STR_PAD_LEFT);

        // Create uncompressed EC point (0x04 + x + y)
        $publicKey = "\x04" . $x . $y;

        return new OpenSslKeyPair($keyResource, $publicKey, $this);
    }

    private function getCoordinateLength(): int
    {
        return match($this->curveName) {
            'secp256r1' => 32,
            'secp384r1' => 48,
            'secp521r1' => 66,  // 521 bits = 65.125 bytes, padded to 66
            default => throw new CryptoException("Unknown coordinate length for {$this->curveName}")
        };
    }

    public function getPeerPublicKey(string $peerPublicKey): mixed
    {
        // Verify peer public key format (should start with 0x04 for uncompressed)
        if (strlen($peerPublicKey) < 1 || ord($peerPublicKey[0]) !== 0x04) {
            throw new CryptoException('Invalid peer public key format');
        }

        // Extract x and y from peer public key
        $pointLen = (strlen($peerPublicKey) - 1) / 2;
        $peerX = substr($peerPublicKey, 1, $pointLen);
        $peerY = substr($peerPublicKey, 1 + $pointLen, $pointLen);

        $peerKeyResource = openssl_pkey_new([
            'ec' => [
                'curve_name' => $this->opensslCurveName,
                'x' => $peerX,
                'y' => $peerY,
            ],
        ]);

        if (!$peerKeyResource) {
            throw new CryptoException('Failed to create peer public key resource');
        }

        return $peerKeyResource;
    }
}
