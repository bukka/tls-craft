<?php

namespace Php\TlsCraft\Session;

use Php\TlsCraft\Exceptions\CraftException;

/**
 * Interface for session ticket storage backends
 *
 * Allows different storage implementations (in-memory, file-based, Redis, etc.)
 */
interface SessionStorage
{
    /**
     * Store a session ticket
     *
     * @param string        $serverName Server name (SNI) this ticket is for
     * @param SessionTicket $ticket     The ticket to store
     *
     * @throws CraftException If storage fails
     */
    public function store(string $serverName, SessionTicket $ticket): void;

    /**
     * Retrieve a session ticket for a server
     *
     * Returns the most recent valid ticket for the given server.
     * Returns null if no valid ticket exists.
     *
     * @param string $serverName Server name (SNI) to get ticket for
     *
     * @return SessionTicket|null The ticket or null if not found/expired
     */
    public function retrieve(string $serverName): ?SessionTicket;

    /**
     * Retrieve all valid tickets for a server
     *
     * @param string $serverName Server name (SNI) to get tickets for
     *
     * @return SessionTicket[] Array of valid tickets (may be empty)
     */
    public function retrieveAll(string $serverName): array;

    /**
     * Remove a specific ticket
     *
     * @param string $serverName     Server name
     * @param string $ticketIdentity The ticket identity to remove
     */
    public function remove(string $serverName, string $ticketIdentity): void;

    /**
     * Remove all tickets for a server
     *
     * @param string $serverName Server name
     */
    public function removeAll(string $serverName): void;

    /**
     * Remove all expired tickets from storage
     *
     * @return int Number of tickets removed
     */
    public function cleanup(): int;

    /**
     * Clear all stored tickets
     */
    public function clear(): void;

    /**
     * Check if storage has any tickets for a server
     *
     * @param string $serverName Server name
     *
     * @return bool True if at least one valid ticket exists
     */
    public function has(string $serverName): bool;

    /**
     * Get count of valid tickets for a server
     *
     * @param string $serverName Server name
     *
     * @return int Number of valid tickets
     */
    public function count(string $serverName): int;
}
