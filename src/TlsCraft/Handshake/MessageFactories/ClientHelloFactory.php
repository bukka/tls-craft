<?php

namespace Php\TlsCraft\Messages\Factories;

use Php\TlsCraft\Messages\ClientHello;
use Php\TlsCraft\Protocol\Version;

class ClientHelloFactory extends AbstractMessageFactory
{
    public function create(): ClientHello
    {
        $extensions = $this->config->clientHelloExtensions->createExtensions($this->context);

        return new ClientHello(
            Version::TLS_1_2, // Legacy version field
            $this->context->getClientRandom(),
            '', // Empty session ID for TLS 1.3
            $this->config->cipherSuites,
            [0], // Null compression
            $extensions
        );
    }
}