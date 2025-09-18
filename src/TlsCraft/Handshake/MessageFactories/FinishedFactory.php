<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Handshake\Messages\Finished;

class FinishedFactory extends AbstractMessageFactory
{
    public function create(bool $isClient): Finished
    {
        $finishedData = $this->context->getFinishedData($isClient);
        return new Finished($finishedData);
    }
}
