<?php

namespace Php\TlsCraft\Handshake\Messages;

use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Handshake\Extensions\Extension;
use Php\TlsCraft\Protocol\HandshakeType;
use Php\TlsCraft\Protocol\Version;

class ServerHello extends Message
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
            throw new ProtocolViolationException('ServerHello random must be 32 bytes');
        }
    }

    public function encode(): string
    {
        $encoded = $this->version->toBytes();
        $encoded .= $this->random;

        // Session ID
        $encoded .= chr(strlen($this->sessionId)).$this->sessionId;

        // Cipher suite (2 bytes)
        $encoded .= pack('n', $this->cipherSuite->value);

        // Compression method (1 byte)
        $encoded .= chr($this->compressionMethod);

        // Extensions
        $encoded .= Extension::encodeList($this->extensions);

        return $encoded;
    }
}
