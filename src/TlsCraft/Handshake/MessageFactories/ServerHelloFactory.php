<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Handshake\Extensions\Extension;
use Php\TlsCraft\Handshake\Messages\ServerHello;
use Php\TlsCraft\Protocol\HandshakeType;
use Php\TlsCraft\Protocol\Version;

class ServerHelloFactory extends AbstractMessageFactory
{
    public function create(): ServerHello
    {
        $extensions = $this->config->getServerHelloExtensions()->createExtensions($this->context);

        $negotiatedCipher = $this->context->getNegotiatedCipherSuite();
        if ($negotiatedCipher === null) {
            throw new CraftException('No cipher suite negotiated');
        }

        return new ServerHello(
            Version::TLS_1_2, // Legacy version field
            $this->context->getServerRandom(),
            '', // Empty session ID for TLS 1.3
            $negotiatedCipher,
            0, // Null compression
            $extensions,
        );
    }

    public function fromWire(string $data, int &$offset = 0): ServerHello
    {
        $payload = $this->parseHandshake($data, HandshakeType::SERVER_HELLO);

        $offset = 0;

        // Version (2 bytes)
        $version = Version::fromBytes(substr($payload, $offset, 2));
        $offset += 2;

        // Random (32 bytes)
        $random = substr($payload, $offset, 32);
        $offset += 32;

        // Session ID
        $sessionIdLength = ord($payload[$offset]);
        ++$offset;
        $sessionId = substr($payload, $offset, $sessionIdLength);
        $offset += $sessionIdLength;

        // Cipher suite (2 bytes)
        $cipherSuite = CipherSuite::from(unpack('n', substr($payload, $offset, 2))[1]);
        $offset += 2;

        // Compression method (1 byte)
        $compressionMethod = ord($payload[$offset]);
        ++$offset;

        // Extensions
        $extensions = Extension::decodeList($payload, $offset);

        return new ServerHello($version, $random, $sessionId, $cipherSuite, $compressionMethod, $extensions);
    }
}
