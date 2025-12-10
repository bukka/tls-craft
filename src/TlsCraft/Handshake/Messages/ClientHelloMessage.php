<?php

namespace Php\TlsCraft\Handshake\Messages;

use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Protocol\HandshakeType;
use Php\TlsCraft\Protocol\Version;

class ClientHelloMessage extends Message
{
    public function __construct(
        public readonly Version $version,
        public readonly string $random, // 32 bytes
        public readonly string $sessionId,
        public readonly array $cipherSuites, // array of int
        public readonly array $compressionMethods, // array of int
        array $extensions, // array of Extension
    ) {
        parent::__construct(HandshakeType::CLIENT_HELLO, $extensions);

        if (strlen($random) !== 32) {
            throw new ProtocolViolationException('ClientHelloMessage random must be 32 bytes');
        }
    }
}
