<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Exceptions\CryptoException;

class CryptoFactory
{
    public function createAead(string $key, string $iv, CipherSuite $cipherSuite): Aead
    {
        return new Aead($key, $iv, $cipherSuite);
    }

    public function createKeyExchange(NamedGroup $group): KeyExchange
    {
        return match ($group) {
            NamedGroup::SECP256R1 => new EcdhKeyExchange('secp256r1'),
            NamedGroup::SECP384R1 => new EcdhKeyExchange('secp384r1'),
            NamedGroup::SECP521R1 => new EcdhKeyExchange('secp521r1'),
            NamedGroup::X25519 => new X25519KeyExchange(),
            NamedGroup::X448 => new X448KeyExchange(),
            default => throw new CryptoException("Unsupported group: {$group->getName()}"),
        };
    }

    public function createKeySchedule(CipherSuite $cipherSuite): KeySchedule
    {
        return new KeySchedule($cipherSuite, new KeyDerivation());
    }

    public function createRandomGenerator(): RandomGenerator
    {
        return new RandomGenerator();
    }
}
