<?php

namespace Php\TlsCraft\Connection;

interface Handle
{
    public function read(int $length): string;

    public function write(string $data): int;

    public function accept(?float $timeout = null): Handle;

    public function isConnected(): bool;

    public function close(): void;

    public function getLocalName(): string;

    public function getPeerName(): string;

    public function setTimeout(float $timeout): void;

    public function setBlocking(bool $blocking): void;

    public function select(array $otherHandles, float $timeout, bool $checkWrite): array;
}