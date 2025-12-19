<?php

namespace Php\TlsCraft\Session;

/**
 * Interface for session ticket serialization
 * Handles converting SessionTicketData to/from opaque ticket bytes
 */
interface SessionTicketSerializer
{
    /**
     * Serialize ticket data into opaque ticket bytes
     */
    public function serialize(SessionTicketData $data): string;

    /**
     * Unserialize opaque ticket bytes into structured data
     * Returns SessionTicketData or null if unserialization fails
     */
    public function unserialize(string $ticket): ?SessionTicketData;
}
