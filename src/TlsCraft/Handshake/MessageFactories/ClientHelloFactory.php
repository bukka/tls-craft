<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Handshake\Extensions\Extension;
use Php\TlsCraft\Handshake\Messages\ClientHello;
use Php\TlsCraft\Protocol\HandshakeType;
use Php\TlsCraft\Protocol\Version;

class ClientHelloFactory extends AbstractMessageFactory
{
    public function create(): ClientHello
    {
        $extensions = $this->config->getClientHelloExtensions()->createExtensions($this->context);

        return new ClientHello(
            Version::TLS_1_2, // Legacy version field
            $this->context->getClientRandom(),
            '', // Empty session ID for TLS 1.3
            $this->config->getCipherSuites(),
            [0], // Null compression
            $extensions,
        );
    }

    public function fromWire(string $data): ClientHello
    {
        $payload = $this->parseHandshake($data, HandshakeType::CLIENT_HELLO);

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

        // Cipher suites
        $cipherSuitesLength = unpack('n', substr($payload, $offset, 2))[1];
        $offset += 2;

        $cipherSuites = [];
        for ($i = 0; $i < $cipherSuitesLength; $i += 2) {
            $cipherSuites[] = unpack('n', substr($payload, $offset + $i, 2))[1];
        }
        $offset += $cipherSuitesLength;

        // Compression methods
        $compressionLength = ord($payload[$offset]);
        ++$offset;

        $compressionMethods = [];
        for ($i = 0; $i < $compressionLength; ++$i) {
            $compressionMethods[] = ord($payload[$offset + $i]);
        }
        $offset += $compressionLength;

        // Extensions
        $extensions = Extension::decodeList($payload, $offset);

        return new ClientHello($version, $random, $sessionId, $cipherSuites, $compressionMethods, $extensions);
    }
}
