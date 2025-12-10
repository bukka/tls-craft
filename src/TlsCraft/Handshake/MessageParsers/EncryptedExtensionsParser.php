<?php

namespace Php\TlsCraft\Handshake\MessageParsers;

use Php\TlsCraft\Handshake\Extensions\Extension;
use Php\TlsCraft\Handshake\Messages\EncryptedExtensionsMessage;
use Php\TlsCraft\Protocol\HandshakeType;

class EncryptedExtensionsParser extends AbstractMessageParser
{
    public function parse(string $data): EncryptedExtensionsMessage
    {
        $payload = $this->parseHandshake($data, HandshakeType::ENCRYPTED_EXTENSIONS);

        $offset = 0;
        $extensions = $this->extensionFactory->decodeExtensionList($payload, $offset);

        return new EncryptedExtensionsMessage($extensions);
    }
}
