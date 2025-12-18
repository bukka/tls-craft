<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Handshake\Messages\NewSessionTicketMessage;
use Php\TlsCraft\Logger;

class NewSessionTicketFactory extends AbstractMessageFactory
{
    /**
     * Create NewSessionTicket message
     */
    public function create(): NewSessionTicketMessage
    {
        // Generate ticket nonce
        $ticketNonce = random_bytes(32);

        // Get resumption master secret from context
        $resumptionMasterSecret = $this->context->getResumptionMasterSecret();

        if ($resumptionMasterSecret === null) {
            // Derive it if not already derived
            $resumptionMasterSecret = $this->context->getKeySchedule()
                ->deriveResumptionMasterSecret();
            $this->context->setResumptionMasterSecret($resumptionMasterSecret);
        }

        // Derive resumption secret (PSK) from nonce
        $resumptionSecret = $this->context->getKeySchedule()
            ->deriveResumptionSecret($resumptionMasterSecret, $ticketNonce);

        // Create opaque ticket data
        $ticket = $this->createTicket($resumptionSecret, $ticketNonce);

        // Get configuration
        $config = $this->context->getConfig();
        $ticketLifetime = $config->getSessionLifetime();
        $ticketAgeAdd = random_int(0, 0xFFFFFFFF);

        Logger::debug('Created NewSessionTicket', [
            'lifetime' => $ticketLifetime,
            'nonce' => bin2hex($ticketNonce),
            'ticket_length' => strlen($ticket),
        ]);

        return new NewSessionTicketMessage(
            ticketLifetime: $ticketLifetime,
            ticketAgeAdd: $ticketAgeAdd,
            ticketNonce: $ticketNonce,
            ticket: $ticket,
            extensions: [], // Could include early_data extension for 0-RTT
        );
    }

    /**
     * Create opaque ticket data
     */
    private function createTicket(string $resumptionSecret, string $nonce): string
    {
        $ticketData = [
            'version' => 1,
            'cipher_suite' => $this->context->getNegotiatedCipherSuite()->value,
            'resumption_secret' => $resumptionSecret,
            'nonce' => $nonce,
            'timestamp' => time(),
            'server_name' => $this->context->getRequestedServerName(),
            'max_early_data' => $this->config->getMaxEarlyDataSize(),
        ];

        // TODO: encrypt + MAC this data with a server key
        // For now: just serialize (easier to debug)
        return serialize($ticketData);
    }
}
