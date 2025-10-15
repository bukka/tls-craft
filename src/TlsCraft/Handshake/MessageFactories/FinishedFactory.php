<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Handshake\Messages\Finished;
use Php\TlsCraft\Protocol\HandshakeType;

class FinishedFactory extends AbstractMessageFactory
{
    public function create(bool $isClient): Finished
    {
        $finishedData = $this->context->getFinishedData($isClient);

        return new Finished($finishedData);
    }

    public function fromWire(string $data): Finished
    {
        $payload = $this->parseHandshake($data, HandshakeType::FINISHED);

        return new Finished($payload);
    }
}
