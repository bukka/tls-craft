<?php

namespace Php\TlsCraft\Control;

class ScheduledAction
{
    public function __construct(
        public readonly float $executeAt,
        public readonly string $eventType,
        public readonly array $eventData,
        public readonly string $description
    ) {}

    public function shouldExecute(float $currentTime): bool
    {
        return $currentTime >= $this->executeAt;
    }

    public function createEvent(): ControlEvent
    {
        return new ControlEvent($this->eventType, $this->eventData);
    }
}