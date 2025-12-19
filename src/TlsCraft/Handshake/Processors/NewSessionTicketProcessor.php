<?php

namespace Php\TlsCraft\Handshake\Processors;

use Php\TlsCraft\Config;
use Php\TlsCraft\Context;
use Php\TlsCraft\Handshake\Messages\NewSessionTicketMessage;
use Php\TlsCraft\Logger;
use Php\TlsCraft\Session\SessionTicketFactory;

class NewSessionTicketProcessor extends MessageProcessor
{
    public function __construct(
        Context $context,
        Config $config,
        private readonly SessionTicketFactory $ticketFactory,
    ) {
        parent::__construct($context, $config);
    }

    public function process(NewSessionTicketMessage $message): void
    {
        Logger::debug('Processing NewSessionTicket', [
            'lifetime' => $message->ticketLifetime,
            'ticket_length' => strlen($message->ticket),
        ]);

        // Create SessionTicket (opaque or decrypted)
        $sessionTicket = $this->ticketFactory->createFromMessage($message);

        Logger::debug('Created SessionTicket', [
            'is_opaque' => $sessionTicket->isOpaque(),
            'server_name' => $sessionTicket->serverName,
        ]);

        // Store ticket if storage is configured
        $storage = $this->context->getConfig()->getSessionStorage();
        if ($storage !== null && $sessionTicket->serverName !== null) {
            $storage->store($sessionTicket->serverName, $sessionTicket);

            Logger::debug('Stored session ticket', [
                'server_name' => $sessionTicket->serverName,
                'is_opaque' => $sessionTicket->isOpaque(),
            ]);
        }

        // Call user callback if configured
        $callback = $this->context->getConfig()->getOnSessionTicket();
        if ($callback !== null) {
            $callback($sessionTicket);
        }
    }
}
