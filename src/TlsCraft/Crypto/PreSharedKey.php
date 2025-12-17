<?php

namespace Php\TlsCraft\Crypto;

/**
 * Pre-Shared Key (PSK) - contains the secret and metadata
 */
class PreSharedKey
{
    public function __construct(
        public readonly string $identity,
        public readonly string $secret,
        public readonly CipherSuite $cipherSuite,
        public readonly int $maxEarlyDataSize = 0,
    ) {
    }

    /**
     * Create external PSK (manually configured, not from ticket)
     */
    public static function external(
        string $identity,
        string $secret,
        CipherSuite $cipherSuite,
    ): self {
        return new self($identity, $secret, $cipherSuite);
    }

    /**
     * Get hash algorithm for this PSK based on cipher suite
     */
    public function getHashAlgorithm(): string
    {
        return $this->cipherSuite->getHashAlgorithm();
    }

    /**
     * Get hash length in bytes
     */
    public function getHashLength(): int
    {
        return $this->cipherSuite->getHashLength();
    }
}
