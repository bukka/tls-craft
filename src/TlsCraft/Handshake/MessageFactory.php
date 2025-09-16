<?php

namespace Php\TlsCraft\Messages;

use Php\TlsCraft\Config;
use Php\TlsCraft\Context;
use Php\TlsCraft\Crypto\RandomGenerator;
use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Protocol\AlertDescription;
use Php\TlsCraft\Protocol\AlertLevel;
use Php\TlsCraft\Protocol\Version;

class MessageFactory
{

    private Config $config;

    public function __construct(
        private Context $context
    )
    {
        $this->config = $context->getConfig();
    }

    public function createClientHello(): ClientHello
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

    public function createServerHello(Context $context): ServerHello
    {
        $extensions = $this->config->serverHelloExtensions->createExtensions($context);

        $negotiatedCipher = $context->getNegotiatedCipherSuite();
        if ($negotiatedCipher === null) {
            throw new CraftException("No cipher suite negotiated");
        }

        return new ServerHello(
            Version::TLS_1_2, // Legacy version field
            $context->getServerRandom() ?? RandomGenerator::generateServerRandom(),
            '', // Empty session ID for TLS 1.3
            $negotiatedCipher->value,
            0, // Null compression
            $extensions
        );
    }

    public function createEncryptedExtensions(Context $context): EncryptedExtensions
    {
        $extensions = $this->config->encryptedExtensions->createExtensions($context);

        return new EncryptedExtensions($extensions);
    }

    public function createCertificate(Context $context, array $certificateChain): Certificate
    {
        return new Certificate('', $certificateChain);
    }

    public function createCertificateVerify(Context $context, string $signature): CertificateVerify
    {
        $signatureScheme = $context->getNegotiatedSignatureScheme();
        if ($signatureScheme === null) {
            throw new CraftException("No signature scheme negotiated");
        }

        return new CertificateVerify($signatureScheme->value, $signature);
    }

    public function createFinished(Context $context, bool $isClient): Finished
    {
        $finishedData = $context->getFinishedData($isClient);
        return new Finished($finishedData);
    }

    public function createKeyUpdate(bool $requestUpdate): KeyUpdate
    {
        return new KeyUpdate($requestUpdate);
    }

    public function createAlert(AlertLevel $level, AlertDescription $description): string
    {
        return $level->toByte() . $description->toByte();
    }
}