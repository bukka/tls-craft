<?php

namespace Php\TlsCraft\Handshake\Messages;

use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Handshake\Extensions\Extension;
use Php\TlsCraft\Protocol\HandshakeType;
use Php\TlsCraft\Protocol\Version;

class ClientHello extends Message
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
            throw new ProtocolViolationException('ClientHello random must be 32 bytes');
        }
    }

    public function encode(): string
    {
        $encoded = $this->version->toBytes();
        $encoded .= $this->random;

        // Session ID (length-prefixed)
        $encoded .= chr(strlen($this->sessionId)).$this->sessionId;

        // Cipher suites (length-prefixed, 2 bytes per suite)
        $cipherSuitesData = '';
        foreach ($this->cipherSuites as $suite) {
            $cipherSuitesData .= pack('n', $suite);
        }
        $encoded .= pack('n', strlen($cipherSuitesData)).$cipherSuitesData;

        // Compression methods (length-prefixed, 1 byte per method)
        $compressionData = '';
        foreach ($this->compressionMethods as $method) {
            $compressionData .= chr($method);
        }
        $encoded .= chr(strlen($compressionData)).$compressionData;

        // Extensions
        $encoded .= Extension::encodeList($this->extensions);

        return $encoded;
    }
}
