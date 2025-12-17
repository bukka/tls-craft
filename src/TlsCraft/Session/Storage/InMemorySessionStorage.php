<?php

namespace Php\TlsCraft\Session\Storage;

use Php\TlsCraft\Session\SessionStorage;
use Php\TlsCraft\Session\SessionTicket;

/**
 * In-memory session storage implementation
 *
 * Stores tickets in memory for the lifetime of the process.
 * Useful for testing or short-lived applications.
 */
class InMemorySessionStorage implements SessionStorage
{
    /**
     * Storage structure: [serverName => [ticketIdentity => SessionTicket]]
     *
     * @var array<string, array<string, SessionTicket>>
     */
    private array $storage = [];

    public function store(string $serverName, SessionTicket $ticket): void
    {
        if (!isset($this->storage[$serverName])) {
            $this->storage[$serverName] = [];
        }

        $this->storage[$serverName][$ticket->getIdentity()] = $ticket;
    }

    public function retrieve(string $serverName): ?SessionTicket
    {
        if (!isset($this->storage[$serverName])) {
            return null;
        }

        // Find the most recent valid ticket
        $validTickets = array_filter(
            $this->storage[$serverName],
            fn (SessionTicket $ticket) => !$ticket->isExpired(),
        );

        if (empty($validTickets)) {
            return null;
        }

        // Sort by timestamp descending (most recent first)
        usort($validTickets, fn ($a, $b) => $b->timestamp <=> $a->timestamp);

        return $validTickets[0];
    }

    public function retrieveAll(string $serverName): array
    {
        if (!isset($this->storage[$serverName])) {
            return [];
        }

        // Return all valid tickets
        return array_values(array_filter(
            $this->storage[$serverName],
            fn (SessionTicket $ticket) => !$ticket->isExpired(),
        ));
    }

    public function remove(string $serverName, string $ticketIdentity): void
    {
        if (isset($this->storage[$serverName][$ticketIdentity])) {
            unset($this->storage[$serverName][$ticketIdentity]);

            // Clean up empty server entries
            if (empty($this->storage[$serverName])) {
                unset($this->storage[$serverName]);
            }
        }
    }

    public function removeAll(string $serverName): void
    {
        unset($this->storage[$serverName]);
    }

    public function cleanup(): int
    {
        $removed = 0;

        foreach ($this->storage as $serverName => $tickets) {
            foreach ($tickets as $identity => $ticket) {
                if ($ticket->isExpired()) {
                    unset($this->storage[$serverName][$identity]);
                    ++$removed;
                }
            }

            // Clean up empty server entries
            if (empty($this->storage[$serverName])) {
                unset($this->storage[$serverName]);
            }
        }

        return $removed;
    }

    public function clear(): void
    {
        $this->storage = [];
    }

    public function has(string $serverName): bool
    {
        if (!isset($this->storage[$serverName])) {
            return false;
        }

        // Check if any valid tickets exist
        foreach ($this->storage[$serverName] as $ticket) {
            if (!$ticket->isExpired()) {
                return true;
            }
        }

        return false;
    }

    public function count(string $serverName): int
    {
        if (!isset($this->storage[$serverName])) {
            return 0;
        }

        return count(array_filter(
            $this->storage[$serverName],
            fn (SessionTicket $ticket) => !$ticket->isExpired(),
        ));
    }

    /**
     * Get all server names with stored tickets
     *
     * @return string[]
     */
    public function getServerNames(): array
    {
        return array_keys($this->storage);
    }

    /**
     * Get total ticket count across all servers
     */
    public function getTotalCount(): int
    {
        $total = 0;
        foreach ($this->storage as $tickets) {
            $total += count(array_filter(
                $tickets,
                fn (SessionTicket $ticket) => !$ticket->isExpired(),
            ));
        }

        return $total;
    }
}
