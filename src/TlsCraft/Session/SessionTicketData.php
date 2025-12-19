<?php

namespace Php\TlsCraft\Session;

use Php\TlsCraft\Crypto\CipherSuite;

/**
 * Decrypted session ticket data
 * Contains the actual session state that the server encrypted
 */
class SessionTicketData
{
    public function __construct(
        public readonly string $resumptionSecret,
        public readonly CipherSuite $cipherSuite,
        public readonly int $timestamp,
        public readonly string $nonce,
        public readonly string $serverName,
        public readonly int $maxEarlyDataSize = 0,
        public readonly int $version = 1,
    ) {
    }

    /**
     * Check if ticket is expired
     */
    public function isExpired(int $lifetime): bool
    {
        $age = time() - $this->timestamp;

        return $age >= $lifetime;
    }
}
