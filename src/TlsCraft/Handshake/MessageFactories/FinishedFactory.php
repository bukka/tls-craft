<?php

namespace Php\TlsCraft\Messages\Factories;

use Php\TlsCraft\Messages\Finished;

class FinishedFactory extends AbstractMessageFactory
{
    public function create(bool $isClient): Finished
    {
        $finishedData = $this->context->getFinishedData($isClient);
        return new Finished($finishedData);
    }
}
