<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Exceptions\CraftException;
use ValueError;

/**
 * Key Share entry for TLS 1.3 key exchange
 */
class KeyShare
{
    public function __construct(
        private NamedGroup $group,
        private string $keyExchange,
    ) {
        // Validate key exchange length
        $expectedLength = $this->group->getKeySize();
        if ($expectedLength > 0 && strlen($this->keyExchange) !== $expectedLength) {
            throw new CraftException(
                "Invalid key exchange length for {$this->group->getName()}: expected {$expectedLength}, got " . strlen($this->keyExchange)
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
            throw new CraftException('Insufficient data for key share');
        }

        $groupValue = unpack('n', substr($data, $offset, 2))[1];
        $keyLength = unpack('n', substr($data, $offset + 2, 2))[1];
        $offset += 4;

        if (strlen($data) - $offset < $keyLength) {
            throw new CraftException('Insufficient data for key exchange');
        }

        $keyExchange = substr($data, $offset, $keyLength);
        $offset += $keyLength;

        try {
            $group = NamedGroup::from($groupValue);
        } catch (ValueError $e) {
            throw new CraftException("Unknown named group: {$groupValue}");
        }

        return new self($group, $keyExchange);
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
            NamedGroup::X25519 => strlen($this->keyExchange) === 32,
            NamedGroup::X448 => strlen($this->keyExchange) === 56,
            default => true,
        };
    }

    private function validateECPoint(): bool
    {
        // For ECDH, check if it's a valid uncompressed point (starts with 0x04)
        if ($this->keyExchange === '') {
            return false;
        }

        // Check for uncompressed point format
        if (ord($this->keyExchange[0]) !== 0x04) {
            return false;
        }

        // Verify correct length for uncompressed point: 1 + 2 * coordinate_length
        $expectedLengths = [
            NamedGroup::SECP256R1->value => 65,  // 1 + 32 + 32
            NamedGroup::SECP384R1->value => 97,  // 1 + 48 + 48
            NamedGroup::SECP521R1->value => 133, // 1 + 66 + 66
        ];

        return isset($expectedLengths[$this->group->value])
            && strlen($this->keyExchange) === $expectedLengths[$this->group->value];
    }

    /**
     * Create a KeyShare from a NamedGroup and KeyPair
     * This is a convenience method for use with the CryptoFactory
     */
    public static function fromKeyPair(NamedGroup $group, KeyPair $keyPair): self
    {
        return new self($group, $keyPair->getPublicKey());
    }

    /**
     * Get a debug-friendly representation
     */
    public function __toString(): string
    {
        return sprintf(
            "KeyShare(group=%s, key_length=%d, key_hex=%s...)",
            $this->group->getName(),
            strlen($this->keyExchange),
            substr(bin2hex($this->keyExchange), 0, 16)
        );
    }
}
