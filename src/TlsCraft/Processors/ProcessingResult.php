<?php

namespace Php\TlsCraft\Processors;

use Php\TlsCraft\Messages\HandshakeMessage;
use Php\TlsCraft\State\HandshakeState;

/**
 * Result of processing a message
 */
class ProcessingResult
{
    public function __construct(
        private array $responseMessages = [],
        private ?HandshakeState $newState = null,
        private array $actions = [],
        private bool $shouldContinue = true
    ) {}

    public function getResponseMessages(): array
    {
        return $this->responseMessages;
    }

    public function getNewState(): ?HandshakeState
    {
        return $this->newState;
    }

    public function getActions(): array
    {
        return $this->actions;
    }

    public function shouldContinue(): bool
    {
        return $this->shouldContinue;
    }

    public function addResponseMessage(HandshakeMessage $message): void
    {
        $this->responseMessages[] = $message;
    }

    public function addAction(string $action, array $params = []): void
    {
        $this->actions[] = ['action' => $action, 'params' => $params];
    }

    public function stopProcessing(): void
    {
        $this->shouldContinue = false;
    }
}
