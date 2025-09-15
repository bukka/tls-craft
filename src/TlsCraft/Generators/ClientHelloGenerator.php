<?php

namespace Php\TlsCraft\Generators;

use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Crypto\RandomGenerator;
use Php\TlsCraft\Messages\HandshakeMessage;
use Php\TlsCraft\Messages\ClientHello;
use Php\TlsCraft\Protocol\Version;

class ClientHelloGenerator extends MessageGenerator
{
    public function canGenerate(string $messageType): bool
    {
        return $messageType === 'client_hello';
    }

    public function generate(array $params = []): HandshakeMessage
    {
        return new ClientHello(
            version: Version::TLS_1_3,
            random: $this->context->getClientRandom() ?? RandomGenerator::generate(32),
            sessionId: $params['session_id'] ?? null,
            cipherSuites: $this->config->cipherSuites,
            compressionMethods: [0],
            extensions: $this->config->clientHelloExtensions->createExtensions($this->context),
        );
    }

    private function selectCipherSuite(array $supportedSuites): CipherSuite
    {
        // In real implementation, this would negotiate with client's offered suites
        return $supportedSuites[0] ?? CipherSuite::TLS_AES_128_GCM_SHA256;
    }
}