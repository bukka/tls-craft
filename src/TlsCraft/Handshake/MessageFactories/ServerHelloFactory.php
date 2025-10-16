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
}
