<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Handshake\Messages\ServerHello;
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
            $this->context->getClientHelloSessionId(),
            $negotiatedCipher,
            0, // Null compression
            $extensions,
        );
    }
}
