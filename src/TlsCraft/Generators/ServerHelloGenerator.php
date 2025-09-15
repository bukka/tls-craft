<?php

namespace Php\TlsCraft\Generators;

use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Crypto\RandomGenerator;
use Php\TlsCraft\Messages\HandshakeMessage;
use Php\TlsCraft\Messages\ServerHello;
use Php\TlsCraft\Protocol\Version;

class ServerHelloGenerator extends MessageGenerator
{
    public function canGenerate(string $messageType): bool
    {
        return $messageType === 'server_hello';
    }

    public function generate(array $params = []): HandshakeMessage
    {
        $selectedCipherSuite = $this->context->getNegotiatedCipherSuite();
        if (!$selectedCipherSuite) {
            // Select cipher suite from client's list
            $selectedCipherSuite = $this->selectCipherSuite($this->config->cipherSuites);
            $this->context->setNegotiatedCipherSuite($selectedCipherSuite);
        }

        return new ServerHello(
            version: Version::TLS_1_2, // Wire format
            random: $this->context->getServerRandom() ?? RandomGenerator::generate(32),
            sessionId: $params['session_id'] ?? null,
            cipherSuite: $selectedCipherSuite->value,
            compressionMethod: 0,
            extensions: $this->config->serverHelloExtensions->createExtensions($this->context)
        );
    }

    private function selectCipherSuite(array $supportedSuites): CipherSuite
    {
        // In real implementation, this would negotiate with client's offered suites
        return $supportedSuites[0] ?? CipherSuite::TLS_AES_128_GCM_SHA256;
    }
}