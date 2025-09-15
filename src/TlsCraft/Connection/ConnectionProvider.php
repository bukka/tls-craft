<?php

namespace Php\TlsCraft\Connection;

interface ConnectionProvider
{
    public function __construct(array $options = []);

    public function connect(string $address, int $port, float $timeout): mixed;

    public function bind(string $address, int $port): mixed;

    public function accept(mixed $serverHandle, ?float $timeout = null): mixed;

    public function read(mixed $handle, int $length): string;

    public function write(mixed $handle, string $data): int;

    public function isConnected(mixed $handle): bool;

    public function close(mixed $handle): void;

    public function getLocalName(mixed $handle): string;

    public function getPeerName(mixed $handle): string;

    public function setTimeout(mixed $handle, float $timeout): void;

    public function setBlocking(mixed $handle, bool $blocking): void;

    public function hasDataAvailable(mixed $handle, float $timeout = 0.0): bool;
}