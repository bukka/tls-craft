<?php

namespace Php\TlsCraft\Session;

use Php\TlsCraft\Crypto\CipherSuite;
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
     *
     * For opaque tickets (when serializer fails or is not available), you MUST provide
     * the resumptionSecret and cipherSuite from the current handshake context.
     *
     * @param string|null      $resumptionSecret Required for opaque tickets (the PSK secret)
     * @param CipherSuite|null $cipherSuite      Required for opaque tickets
     */
    public function createFromMessage(
        NewSessionTicketMessage $message,
        ?string $resumptionSecret = null,
        ?CipherSuite $cipherSuite = null,
    ): SessionTicket {
        Logger::debug('Creating SessionTicket from message', [
            'ticket_length' => strlen($message->ticket),
            'lifetime' => $message->ticketLifetime,
            'has_serializer' => $this->serializer !== null,
            'has_resumption_secret' => $resumptionSecret !== null,
            'has_cipher_suite' => $cipherSuite !== null,
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
            // For opaque tickets, store the resumption secret, cipher suite, and timestamp
            resumptionSecret: $ticketData === null ? $resumptionSecret : null,
            cipherSuite: $ticketData === null ? $cipherSuite : null,
            timestamp: $ticketData === null ? time() : null,
        );

        Logger::debug('Created SessionTicket', [
            'is_opaque' => $ticket->isOpaque(),
            'is_valid' => $ticket->isValid(),
            'server_name' => $ticket->getServerName(),
            'identifier' => substr($ticket->getIdentifier(), 0, 16).'...',
        ]);

        return $ticket;
    }
}
