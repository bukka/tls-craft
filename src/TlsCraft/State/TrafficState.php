<?php

declare(strict_types=1);

namespace Php\TlsCraft\State;

/**
 * Application traffic and key state
 */
class TrafficState: string
{
    public function __construct(
        public int     $readSequence = 0,
        public int     $writeSequence = 0,
        public ?string $readKey = null,
        public ?string $writeKey = null,
        public ?string $readIV = null,
        public ?string $writeIV = null,
        public bool    $keyUpdatePending = false
    )
    {
    }

    public function updateKeys(string $readKey, string $writeKey, string $readIV, string $writeIV): void
    {
        $this->readKey = $readKey;
        $this->writeKey = $writeKey;
        $this->readIV = $readIV;
        $this->writeIV = $writeIV;
        $this->keyUpdatePending = false;
    }

    public function incrementReadSequence(): void
    {
        $this->readSequence++;
    }

    public function incrementWriteSequence(): void
    {
        $this->writeSequence++;
    }

    public function scheduleKeyUpdate(): void
    {
        $this->keyUpdatePending = true;
    }

    public function reset(): void
    {
        $this->readSequence = 0;
        $this->writeSequence = 0;
        $this->readKey = null;
        $this->writeKey = null;
        $this->readIV = null;
        $this->writeIV = null;
        $this->keyUpdatePending = false;
    }

    public function hasKeys(): bool
    {
        return $this->readKey !== null && $this->writeKey !== null;
    }
}