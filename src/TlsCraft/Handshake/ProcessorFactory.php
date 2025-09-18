<?php

namespace Php\TlsCraft\Handshake;

use Php\TlsCraft\Config;
use Php\TlsCraft\Context;
use Php\TlsCraft\Handshake\Processors\CertificateProcessor;
use Php\TlsCraft\Handshake\Processors\CertificateVerifyProcessor;
use Php\TlsCraft\Handshake\Processors\ClientHelloProcessor;
use Php\TlsCraft\Handshake\Processors\EncryptedExtensionsProcessor;
use Php\TlsCraft\Handshake\Processors\FinishedProcessor;
use Php\TlsCraft\Handshake\Processors\KeyUpdateProcessor;
use Php\TlsCraft\Handshake\Processors\ServerHelloProcessor;

class ProcessorFactory
{
    private Config $config;

    public function __construct(private Context $context)
    {
        $this->config = $context->getConfig();
    }

    public function createClientHelloProcessor(): ClientHelloProcessor
    {
        return new ClientHelloProcessor($this->context, $this->config);
    }

    public function createServerHelloProcessor(): ServerHelloProcessor
    {
        return new ServerHelloProcessor($this->context, $this->config);
    }

    public function createEncryptedExtensionsProcessor(): EncryptedExtensionsProcessor
    {
        return new EncryptedExtensionsProcessor($this->context, $this->config);
    }

    public function createCertificateProcessor(): CertificateProcessor
    {
        return new CertificateProcessor($this->context, $this->config);
    }

    public function createCertificateVerifyProcessor(): CertificateVerifyProcessor
    {
        return new CertificateVerifyProcessor($this->context, $this->config);
    }

    public function createFinishedProcessor(): FinishedProcessor
    {
        return new FinishedProcessor($this->context, $this->config);
    }

    public function createKeyUpdateProcessor(): KeyUpdateProcessor
    {
        return new KeyUpdateProcessor($this->context, $this->config);
    }
}
