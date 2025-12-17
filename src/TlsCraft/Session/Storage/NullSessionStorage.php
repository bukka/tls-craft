<?php

namespace Php\TlsCraft\Session\Storage;

use Php\TlsCraft\Session\SessionStorage;
use Php\TlsCraft\Session\SessionTicket;

/**
 * Null session storage implementation
 *
 * Does not store any tickets. Useful for disabling session resumption
 * or when you want to handle storage yourself via callbacks.
 */
class NullSessionStorage implements SessionStorage
{
    public function store(string $serverName, SessionTicket $ticket): void
    {
        // Do nothing
    }

    public function retrieve(string $serverName): ?SessionTicket
    {
        return null;
    }

    public function retrieveAll(string $serverName): array
    {
        return [];
    }

    public function remove(string $serverName, string $ticketIdentity): void
    {
        // Do nothing
    }

    public function removeAll(string $serverName): void
    {
        // Do nothing
    }

    public function cleanup(): int
    {
        return 0;
    }

    public function clear(): void
    {
        // Do nothing
    }

    public function has(string $serverName): bool
    {
        return false;
    }

    public function count(string $serverName): int
    {
        return 0;
    }
}
