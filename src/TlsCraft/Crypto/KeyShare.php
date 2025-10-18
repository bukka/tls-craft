<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Logger;
use ValueError;

class KeyShare
{
    public function __construct(
        private NamedGroup $group,
        private string $keyExchange,
    ) {
        $expectedLength = $this->group->getKeySize();
        if ($expectedLength > 0 && strlen($this->keyExchange) !== $expectedLength) {
            Logger::warn('KeyShare length mismatch', [
                'Group' => $this->group->getName(),
                'Expected length' => $expectedLength,
                'Actual length' => strlen($this->keyExchange),
                'Key (prefix)' => substr($this->keyExchange, 0, 16),
            ]);
            throw new CraftException(
                "Invalid key exchange length for {$this->group->getName()}: expected {$expectedLength}, got ".strlen(
                    $this->keyExchange
                )
            );
        }

        Logger::debug('KeyShare constructed', [
            'Group' => $this->group->getName(),
            'Key length' => strlen($this->keyExchange),
            'Key (prefix)' => $this->keyExchange,
        ]);
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
        $enc = pack('nn', $this->group->value, strlen($this->keyExchange)).$this->keyExchange;
        Logger::debug('KeyShare encode', [
            'Group' => $this->group->getName(),
            'Key length' => strlen($this->keyExchange),
        ]);

        return $enc;
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
            Logger::warn('KeyShare decode: unknown group', ['Group value' => $groupValue]);
            throw new CraftException("Unknown named group: {$groupValue}");
        }

        Logger::debug('KeyShare decode', [
            'Group' => $group->getName(),
            'Key length' => $keyLength,
            'Key (prefix)' => substr($keyExchange, 0, 16),
        ]);

        return new self($group, $keyExchange);
    }

    public function validate(): bool
    {
        $expectedLength = $this->group->getKeySize();

        if ($expectedLength > 0 && strlen($this->keyExchange) !== $expectedLength) {
            Logger::warn('KeyShare validate: length mismatch', [
                'Group' => $this->group->getName(),
                'Expected' => $expectedLength,
                'Actual' => strlen($this->keyExchange),
            ]);

            return false;
        }

        $ok = match ($this->group) {
            NamedGroup::SECP256R1,
            NamedGroup::SECP384R1,
            NamedGroup::SECP521R1 => $this->validateECPoint(),
            NamedGroup::X25519 => strlen($this->keyExchange) === 32,
            NamedGroup::X448 => strlen($this->keyExchange) === 56,
            default => true,
        };

        Logger::debug('KeyShare validate', [
            'Group' => $this->group->getName(),
            'OK' => $ok ? 'true' : 'false',
        ]);

        return $ok;
    }

    private function validateECPoint(): bool
    {
        if ($this->keyExchange === '') {
            return false;
        }
        if (ord($this->keyExchange[0]) !== 0x04) {
            return false;
        }

        $expectedLengths = [
            NamedGroup::SECP256R1->value => 65,
            NamedGroup::SECP384R1->value => 97,
            NamedGroup::SECP521R1->value => 133,
        ];

        return isset($expectedLengths[$this->group->value])
            && strlen($this->keyExchange) === $expectedLengths[$this->group->value];
    }

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
