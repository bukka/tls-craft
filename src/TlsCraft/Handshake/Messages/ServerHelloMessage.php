<?php

namespace Php\TlsCraft\Handshake\Messages;

use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Protocol\HandshakeType;
use Php\TlsCraft\Protocol\Version;

class ServerHelloMessage extends Message
{
    public function __construct(
        public readonly Version $version,
        public readonly string $random, // 32 bytes
        public readonly string $sessionId,
        public readonly CipherSuite $cipherSuite,
        public readonly int $compressionMethod,
        array $extensions, // array of Extension
    ) {
        parent::__construct(HandshakeType::SERVER_HELLO, $extensions);

        if (strlen($random) !== 32) {
            throw new ProtocolViolationException('ServerHelloMessage random must be 32 bytes');
        }
    }
}
