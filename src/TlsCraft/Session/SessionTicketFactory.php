<?php

namespace Php\TlsCraft\Session;

use Php\TlsCraft\Handshake\Messages\NewSessionTicketMessage;
use Php\TlsCraft\Logger;

class SessionTicketFactory
{
    public function __construct(
        private readonly ?SessionTicketSerializer $serializer = null,
        private readonly ?string $defaultServerName = null,
    ) {
    }

    /**
     * Create SessionTicket from NewSessionTicketMessage
     * Attempts to unserialize ticket if serializer is available, otherwise creates opaque ticket
     */
    public function createFromMessage(NewSessionTicketMessage $message): SessionTicket
    {
        Logger::debug('Creating SessionTicket from message', [
            'ticket_length' => strlen($message->ticket),
            'lifetime' => $message->ticketLifetime,
            'has_serializer' => $this->serializer !== null,
        ]);

        $ticketData = null;

        // Try to unserialize ticket if serializer is available
        if ($this->serializer !== null) {
            $ticketData = $this->serializer->unserialize($message->ticket);

            if ($ticketData !== null) {
                Logger::debug('Successfully unserialized ticket', [
                    'server_name' => $ticketData->serverName,
                    'cipher_suite' => $ticketData->cipherSuite->name,
                ]);
            } else {
                Logger::debug('Could not unserialize ticket (will treat as opaque)');
            }
        }

        // Create ticket (opaque if data is null)
        $ticket = new SessionTicket(
            ticket: $message->ticket,
            data: $ticketData,
            lifetime: $message->ticketLifetime,
            ageAdd: $message->ticketAgeAdd,
            nonce: $message->ticketNonce,
            serverName: $this->defaultServerName,
        );

        Logger::debug('Created SessionTicket', [
            'is_opaque' => $ticket->isOpaque(),
            'server_name' => $ticket->getServerName(),
            'identifier' => substr($ticket->getIdentifier(), 0, 16).'...',
        ]);

        return $ticket;
    }
}
