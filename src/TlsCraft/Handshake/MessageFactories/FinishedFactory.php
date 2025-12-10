<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Handshake\Messages\FinishedMessage;

class FinishedFactory extends AbstractMessageFactory
{
    public function create(bool $isClient): FinishedMessage
    {
        $finishedData = $this->context->getFinishedData($isClient);

        return new FinishedMessage($finishedData);
    }
}
