<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Handshake\Extensions\EarlyDataExtension;
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

        // Get max early data size from config
        $maxEarlyDataSize = $config->getMaxEarlyDataSize();

        // Create ticket data
        $ticketData = new SessionTicketData(
            resumptionSecret: $resumptionSecret,
            cipherSuite: $this->context->getNegotiatedCipherSuite(),
            timestamp: time(),
            nonce: $ticketNonce,
            serverName: $this->context->getRequestedServerName() ?? 'unknown',
            maxEarlyDataSize: $maxEarlyDataSize,
        );

        // Serialize ticket using configured serializer
        $serializer = $config->getSessionTicketSerializer();
        if ($serializer === null) {
            throw new CraftException('Session ticket serializer not configured');
        }

        $ticket = $serializer->serialize($ticketData);

        // Build extensions
        $extensions = [];
        if ($maxEarlyDataSize > 0) {
            $extensions[] = new EarlyDataExtension($maxEarlyDataSize);
        }

        Logger::debug('Created NewSessionTicket', [
            'ticket_length' => strlen($ticket),
            'lifetime' => $config->getSessionLifetime(),
        ]);

        return new NewSessionTicketMessage(
            ticketLifetime: $config->getSessionLifetime(),
            ticketAgeAdd: random_int(0, 0xFFFFFFFF),
            ticketNonce: $ticketNonce,
            ticket: $ticket,
            extensions: $extensions,
        );
    }
}
