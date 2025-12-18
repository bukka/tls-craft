<?php

namespace Php\TlsCraft\Handshake\Processors;

use Php\TlsCraft\Handshake\Messages\NewSessionTicketMessage;
use Php\TlsCraft\Logger;
use Php\TlsCraft\Session\SessionTicket;

class NewSessionTicketProcessor extends MessageProcessor
{
    public function process(NewSessionTicketMessage $message): void
    {
        Logger::debug('Processing NewSessionTicket', [
            'lifetime' => $message->ticketLifetime,
            'ticket_length' => strlen($message->ticket),
        ]);

        // Parse ticket data (in production, decrypt first)
        $ticketData = @unserialize($message->ticket);

        if (!is_array($ticketData)) {
            Logger::warn('Failed to parse ticket data');

            return;
        }

        // Create SessionTicket object
        $sessionTicket = new SessionTicket(
            ticket: $message->ticket,
            resumptionSecret: $ticketData['resumption_secret'],
            cipherSuite: \Php\TlsCraft\Crypto\CipherSuite::from($ticketData['cipher_suite']),
            lifetime: $message->ticketLifetime,
            ageAdd: $message->ticketAgeAdd,
            nonce: $message->ticketNonce,
            timestamp: $ticketData['timestamp'],
            maxEarlyDataSize: $ticketData['max_early_data'] ?? 0,
            serverName: $ticketData['server_name'] ?? null,
        );

        // Store ticket if storage is configured
        $storage = $this->context->getConfig()->getSessionStorage();
        if ($storage !== null && $sessionTicket->serverName !== null) {
            $storage->store($sessionTicket->serverName, $sessionTicket);

            Logger::debug('Stored session ticket', [
                'server_name' => $sessionTicket->serverName,
            ]);
        }

        // Call user callback if configured
        $callback = $this->context->getConfig()->getOnSessionTicket();
        if ($callback !== null) {
            $callback($sessionTicket);
        }
    }
}
