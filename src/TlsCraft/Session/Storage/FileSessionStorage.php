<?php

namespace Php\TlsCraft\Session\Storage;

use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Session\SessionStorage;
use Php\TlsCraft\Session\SessionTicket;

use const LOCK_EX;

/**
 * File-based session storage implementation
 *
 * Stores tickets as serialized PHP files in a directory.
 * Each server gets its own file: {storageDir}/{hash(serverName)}.php
 */
class FileSessionStorage implements SessionStorage
{
    private string $storageDir;
    private int $filePermissions;

    public function __construct(
        ?string $storageDir = null,
        int $filePermissions = 0600,
    ) {
        $this->storageDir = $storageDir ?? sys_get_temp_dir().'/tlscraft-sessions';
        $this->filePermissions = $filePermissions;

        $this->ensureStorageDirectory();
    }

    private function ensureStorageDirectory(): void
    {
        if (!is_dir($this->storageDir)) {
            if (!mkdir($this->storageDir, 0700, true)) {
                throw new CraftException("Failed to create storage directory: {$this->storageDir}");
            }
        }

        if (!is_writable($this->storageDir)) {
            throw new CraftException("Storage directory is not writable: {$this->storageDir}");
        }
    }

    private function getFilePath(string $serverName): string
    {
        $hash = hash('sha256', $serverName);

        return $this->storageDir.'/'.$hash.'.php';
    }

    /**
     * @return array<string, SessionTicket>
     */
    private function loadTickets(string $serverName): array
    {
        $filePath = $this->getFilePath($serverName);

        if (!file_exists($filePath)) {
            return [];
        }

        $data = @file_get_contents($filePath);
        if ($data === false) {
            return [];
        }

        $tickets = @unserialize($data);
        if (!is_array($tickets)) {
            return [];
        }

        return $tickets;
    }

    /**
     * @param array<string, SessionTicket> $tickets
     */
    private function saveTickets(string $serverName, array $tickets): void
    {
        $filePath = $this->getFilePath($serverName);

        if (empty($tickets)) {
            // Remove file if no tickets remain
            if (file_exists($filePath)) {
                @unlink($filePath);
            }

            return;
        }

        $data = serialize($tickets);

        if (@file_put_contents($filePath, $data, LOCK_EX) === false) {
            throw new CraftException("Failed to write ticket file: {$filePath}");
        }

        @chmod($filePath, $this->filePermissions);
    }

    public function store(string $serverName, SessionTicket $ticket): void
    {
        $tickets = $this->loadTickets($serverName);
        $tickets[$ticket->getIdentity()] = $ticket;
        $this->saveTickets($serverName, $tickets);
    }

    public function retrieve(string $serverName): ?SessionTicket
    {
        $tickets = $this->loadTickets($serverName);

        if (empty($tickets)) {
            return null;
        }

        // Find the most recent valid ticket
        $validTickets = array_filter(
            $tickets,
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
        $tickets = $this->loadTickets($serverName);

        return array_values(array_filter(
            $tickets,
            fn (SessionTicket $ticket) => !$ticket->isExpired(),
        ));
    }

    public function remove(string $serverName, string $ticketIdentity): void
    {
        $tickets = $this->loadTickets($serverName);

        if (isset($tickets[$ticketIdentity])) {
            unset($tickets[$ticketIdentity]);
            $this->saveTickets($serverName, $tickets);
        }
    }

    public function removeAll(string $serverName): void
    {
        $filePath = $this->getFilePath($serverName);

        if (file_exists($filePath)) {
            @unlink($filePath);
        }
    }

    public function cleanup(): int
    {
        $removed = 0;
        $files = glob($this->storageDir.'/*.php');

        if ($files === false) {
            return 0;
        }

        foreach ($files as $file) {
            $data = @file_get_contents($file);
            if ($data === false) {
                continue;
            }

            $tickets = @unserialize($data);
            if (!is_array($tickets)) {
                continue;
            }

            $originalCount = count($tickets);
            $tickets = array_filter(
                $tickets,
                fn (SessionTicket $ticket) => !$ticket->isExpired(),
            );

            $removed += $originalCount - count($tickets);

            if (empty($tickets)) {
                @unlink($file);
            } elseif ($originalCount !== count($tickets)) {
                file_put_contents($file, serialize($tickets), LOCK_EX);
            }
        }

        return $removed;
    }

    public function clear(): void
    {
        $files = glob($this->storageDir.'/*.php');

        if ($files !== false) {
            foreach ($files as $file) {
                @unlink($file);
            }
        }
    }

    public function has(string $serverName): bool
    {
        $tickets = $this->loadTickets($serverName);

        foreach ($tickets as $ticket) {
            if (!$ticket->isExpired()) {
                return true;
            }
        }

        return false;
    }

    public function count(string $serverName): int
    {
        $tickets = $this->loadTickets($serverName);

        return count(array_filter(
            $tickets,
            fn (SessionTicket $ticket) => !$ticket->isExpired(),
        ));
    }

    /**
     * Get the storage directory path
     */
    public function getStorageDir(): string
    {
        return $this->storageDir;
    }
}
