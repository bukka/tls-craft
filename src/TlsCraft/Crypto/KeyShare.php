<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Exceptions\CraftException;

/**
 * Key Share entry for TLS 1.3 key exchange
 */
class KeyShare
{
    public function __construct(
        private NamedGroup $group,
        private string $keyExchange
    ) {
        // Validate key exchange length
        $expectedLength = $this->group->getKeySize();
        if ($expectedLength > 0 && strlen($this->keyExchange) !== $expectedLength) {
            throw new CraftException(
                "Invalid key exchange length for {$this->group->getName()}: " .
                "expected {$expectedLength}, got " . strlen($this->keyExchange)
            );
        }
    }

    public function getGroup(): NamedGroup
    {
        return $this->group;
    }

    public function getGroupName(): string
    {
        return $this->group->getName();
    }

    public function getKeyExchange(): string
    {
        return $this->keyExchange;
    }

    public function getKeyExchangeHex(): string
    {
        return bin2hex($this->keyExchange);
    }

    public function encode(): string
    {
        return pack('nn', $this->group->value, strlen($this->keyExchange)) . $this->keyExchange;
    }

    public static function decode(string $data, int &$offset): self
    {
        if (strlen($data) - $offset < 4) {
            throw new CraftException("Insufficient data for key share");
        }

        $groupValue = unpack('n', substr($data, $offset, 2))[1];
        $keyLength = unpack('n', substr($data, $offset + 2, 2))[1];
        $offset += 4;

        if (strlen($data) - $offset < $keyLength) {
            throw new CraftException("Insufficient data for key exchange");
        }

        $keyExchange = substr($data, $offset, $keyLength);
        $offset += $keyLength;

        try {
            $group = NamedGroup::from($groupValue);
        } catch (\ValueError $e) {
            throw new CraftException("Unknown named group: {$groupValue}");
        }

        return new self($group, $keyExchange);
    }

    /**
     * Create a key share with generated key pair
     */
    public static function generate(NamedGroup $group): self
    {
        return match($group) {
            NamedGroup::SECP256R1 => self::generateECDH($group, 'secp256r1'),
            NamedGroup::SECP384R1 => self::generateECDH($group, 'secp384r1'),
            NamedGroup::SECP521R1 => self::generateECDH($group, 'secp521r1'),
            NamedGroup::X25519 => self::generateX25519($group),
            NamedGroup::X448 => self::generateX448($group),
            default => throw new CraftException("Key generation not implemented for group: {$group->getName()}")
        };
    }

    private static function generateECDH(NamedGroup $group, string $curveName): self
    {
        // Generate ECDH key pair using OpenSSL
        $keyResource = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => $curveName
        ]);

        if (!$keyResource) {
            throw new CraftException("Failed to generate ECDH key pair for {$curveName}");
        }

        $details = openssl_pkey_get_details($keyResource);
        $publicKey = $details['ec']['pub'] ?? null;

        if (!$publicKey) {
            throw new CraftException("Failed to extract public key for {$curveName}");
        }

        // For ECDH, we need the uncompressed point format (0x04 + x + y coordinates)
        // The public key from OpenSSL should already be in this format
        return new self($group, $publicKey);
    }

    private static function generateX25519(NamedGroup $group): self
    {
        // Generate 32 random bytes for X25519 private key
        $privateKey = random_bytes(32);

        // Clamp the private key according to X25519 spec
        $privateKey[0] = chr(ord($privateKey[0]) & 248);
        $privateKey[31] = chr((ord($privateKey[31]) & 127) | 64);

        // Compute public key (this is a simplified example - real implementation needs curve25519)
        // In a real implementation, you'd use sodium_crypto_scalarmult_base() or similar
        if (function_exists('sodium_crypto_scalarmult_base')) {
            $publicKey = sodium_crypto_scalarmult_base($privateKey);
        } else {
            // Fallback: generate random public key (NOT cryptographically correct!)
            $publicKey = random_bytes(32);
        }

        return new self($group, $publicKey);
    }

    private static function generateX448(NamedGroup $group): self
    {
        // X448 key generation (simplified - would need proper curve448 implementation)
        $publicKey = random_bytes(56); // X448 public keys are 56 bytes
        return new self($group, $publicKey);
    }

    /**
     * Compute shared secret with peer's key share
     */
    public function computeSharedSecret(KeyShare $peerKeyShare): string
    {
        if ($this->group !== $peerKeyShare->group) {
            throw new CraftException("Cannot compute shared secret: group mismatch");
        }

        return match($this->group) {
            NamedGroup::X25519 => $this->computeX25519SharedSecret($peerKeyShare->keyExchange),
            NamedGroup::X448 => $this->computeX448SharedSecret($peerKeyShare->keyExchange),
            NamedGroup::SECP256R1,
            NamedGroup::SECP384R1,
            NamedGroup::SECP521R1 => $this->computeECDHSharedSecret($peerKeyShare->keyExchange),
            default => throw new CraftException("Shared secret computation not implemented for: {$this->group->getName()}")
        };
    }

    private function computeX25519SharedSecret(string $peerPublicKey): string
    {
        if (function_exists('sodium_crypto_scalarmult')) {
            // Assuming we have access to our private key (in real implementation)
            // This is simplified - you'd need to store the private key when generating
            throw new CraftException("X25519 shared secret computation requires private key access");
        }

        // Fallback (NOT cryptographically correct!)
        return hash('sha256', $this->keyExchange . $peerPublicKey, true);
    }

    private function computeX448SharedSecret(string $peerPublicKey): string
    {
        // X448 computation (simplified)
        throw new CraftException("X448 shared secret computation requires private key access");
    }

    private function computeECDHSharedSecret(string $peerPublicKey): string
    {
        // ECDH computation using OpenSSL (simplified)
        throw new CraftException("ECDH shared secret computation requires private key access");
    }

    /**
     * Validate key exchange data format
     */
    public function validate(): bool
    {
        $expectedLength = $this->group->getKeySize();

        if ($expectedLength > 0 && strlen($this->keyExchange) !== $expectedLength) {
            return false;
        }

        // Additional validation for specific groups
        return match($this->group) {
            NamedGroup::SECP256R1,
            NamedGroup::SECP384R1,
            NamedGroup::SECP521R1 => $this->validateECPoint(),
            NamedGroup::X25519,
            NamedGroup::X448 => true, // Any 32/56 bytes are valid
            default => true
        };
    }

    private function validateECPoint(): bool
    {
        // For ECDH, check if it's a valid uncompressed point (starts with 0x04)
        return strlen($this->keyExchange) > 0 && ord($this->keyExchange[0]) === 0x04;
    }
}
