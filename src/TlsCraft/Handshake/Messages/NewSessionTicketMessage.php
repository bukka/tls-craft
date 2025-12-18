<?php

namespace Php\TlsCraft\Handshake\Messages;

use Php\TlsCraft\Protocol\HandshakeType;

/**
 * NewSessionTicket message (RFC 8446 Section 4.6.1)
 *
 * Sent by server after handshake to provide resumption ticket
 */
class NewSessionTicketMessage extends Message
{
    public function __construct(
        public readonly int $ticketLifetime,      // seconds
        public readonly int $ticketAgeAdd,        // obfuscation value
        public readonly string $ticketNonce,      // nonce for PSK derivation
        public readonly string $ticket,           // opaque ticket data
        array $extensions = [],
    ) {
        parent::__construct(HandshakeType::NEW_SESSION_TICKET, $extensions);
    }
}
