<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Handshake\Messages\NewSessionTicketMessage;
use Php\TlsCraft\Logger;
use Php\TlsCraft\Session\SessionTicketData;

class NewSessionTicketFactory extends AbstractMessageFactory
{
    public function create(): NewSessionTicketMessage
    {
        $config = $this->context->getConfig();

        if (!$config->isSessionResumptionEnabled()) {
            throw new CraftException('Cannot create NewSessionTicket: resumption not enabled');
        }

        // Generate ticket nonce
        $ticketNonce = random_bytes(32);

        // Derive resumption secret
        $resumptionSecret = $this->context->deriveResumptionSecret($ticketNonce);

        // Create ticket data
        $ticketData = new SessionTicketData(
            resumptionSecret: $resumptionSecret,
            cipherSuite: $this->context->getNegotiatedCipherSuite(),
            timestamp: time(),
            nonce: $ticketNonce,
            serverName: $config->getServerName() ?? 'unknown',
            maxEarlyDataSize: 0, // No early data support yet
        );

        // Serialize ticket using configured serializer
        $serializer = $config->getSessionTicketSerializer();
        if ($serializer === null) {
            throw new CraftException('Session ticket serializer not configured');
        }

        $ticket = $serializer->serialize($ticketData);

        Logger::debug('Created NewSessionTicket', [
            'ticket_length' => strlen($ticket),
            'lifetime' => $config->getSessionLifetime(),
        ]);

        return new NewSessionTicketMessage(
            ticketLifetime: $config->getSessionLifetime(),
            ticketAgeAdd: random_int(0, 0xFFFFFFFF),
            ticketNonce: $ticketNonce,
            ticket: $ticket,
            extensions: [],
        );
    }
}
