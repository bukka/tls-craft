<?php

namespace Php\TlsCraft\Handshake\MessageFactories;

use Php\TlsCraft\Handshake\Messages\ClientHello;
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
            $extensions
        );
    }
}