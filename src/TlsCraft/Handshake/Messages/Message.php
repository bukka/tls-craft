<?php

namespace Php\TlsCraft\Handshake\Messages;

use Php\TlsCraft\Handshake\Extensions\Extension;
use Php\TlsCraft\Handshake\ExtensionType;
use Php\TlsCraft\Protocol\HandshakeType;

abstract class Message
{
    public function __construct(
        public readonly HandshakeType $type,
        public readonly array $extensions = [],
    ) {
    }

    public function getExtension(ExtensionType $type): ?Extension
    {
        return array_find($this->extensions, fn (Extension $extension) => $extension->type->value === $type->value);
    }
}
