<?php

namespace Php\TlsCraft\Handshake\MessageParsers;

use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Handshake\Messages\ServerHelloMessage;
use Php\TlsCraft\Protocol\HandshakeType;
use Php\TlsCraft\Protocol\Version;

class ServerHelloParser extends AbstractMessageParser
{
    public function parse(string $data, int &$offset = 0): ServerHelloMessage
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
        $extensions = $this->extensionFactory->decodeExtensionList($payload, $offset);

        return new ServerHelloMessage($version, $random, $sessionId, $cipherSuite, $compressionMethod, $extensions);
    }
}
