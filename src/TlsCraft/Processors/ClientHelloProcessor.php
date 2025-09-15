<?php

namespace Php\TlsCraft\Processors;

use Php\TlsCraft\Messages\ClientHello;
use Php\TlsCraft\Messages\HandshakeMessage;

class ClientHelloProcessor extends MessageProcessor
{
    public function canProcess(HandshakeMessage $message): bool
    {
        return $message instanceof ClientHello;
    }

    public function process(HandshakeMessage $message): ProcessingResult
    {
        /** @var \Php\TlsCraft\Messages\ClientHello $clientHello */
        $clientHello = $message;

        // Use existing context method
        $this->context->processClientHello($clientHello);

        return new ProcessingResult([], $this->context->getHandshakeState());
    }
}