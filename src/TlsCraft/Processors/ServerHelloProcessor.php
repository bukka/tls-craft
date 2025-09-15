<?php

namespace Php\TlsCraft\Processors;

use Php\TlsCraft\Messages\HandshakeMessage;

class ServerHelloProcessor extends MessageProcessor
{
    public function canProcess(HandshakeMessage $message): bool
    {
        return $message instanceof \Php\TlsCraft\Messages\ServerHello;
    }

    public function process(HandshakeMessage $message): ProcessingResult
    {
        /** @var \Php\TlsCraft\Messages\ServerHello $serverHello */
        $serverHello = $message;

        // Use existing context method
        $this->context->processServerHello($serverHello);

        return new ProcessingResult([], $this->context->getHandshakeState());
    }
}