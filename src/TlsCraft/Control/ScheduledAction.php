<?php

namespace Php\TlsCraft\Control;

class ScheduledAction
{
    public function __construct(
        public readonly float $executeAt,
        public readonly \Closure $action,
        public readonly string $description
    ) {}

    public function shouldExecute(float $currentTime): bool
    {
        return $currentTime >= $this->executeAt;
    }

    public function execute(): void
    {
        ($this->action)();
    }
}