<?php

namespace Php\TlsCraft\Generators;

use Php\TlsCraft\Messages\HandshakeMessage;
use Php\TlsCraft\Messages\KeyUpdate;

class KeyUpdateGenerator
{
    public function canGenerate(string $messageType): bool
    {
        return $messageType === 'key_update';
    }

    public function generate(array $params = []): HandshakeMessage
    {
        return new KeyUpdate($params['request_update'] ?? false);
    }
}