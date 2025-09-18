<?php

namespace Php\TlsCraft\Handshake;

use Php\TlsCraft\Handshake\Messages\Certificate;
use Php\TlsCraft\Handshake\Messages\CertificateVerify;
use Php\TlsCraft\Handshake\Messages\ClientHello;
use Php\TlsCraft\Handshake\Messages\EncryptedExtensions;
use Php\TlsCraft\Handshake\Messages\Finished;
use Php\TlsCraft\Handshake\Messages\KeyUpdate;
use Php\TlsCraft\Handshake\Messages\Message;
use Php\TlsCraft\Handshake\Processors\{CertificateProcessor,
    CertificateVerifyProcessor,
    ClientHelloProcessor,
    EncryptedExtensionsProcessor,
    FinishedProcessor,
    KeyUpdateProcessor,
    ServerHelloProcessor};
use Php\TlsCraft\Handshake\Messages\ServerHello;

class ProcessorManager
{
    private ProcessorFactory $factory;

    // Cached processor instances
    private ?ClientHelloProcessor $clientHelloProcessor = null;
    private ?ServerHelloProcessor $serverHelloProcessor = null;
    private ?EncryptedExtensionsProcessor $encryptedExtensionsProcessor = null;
    private ?CertificateProcessor $certificateProcessor = null;
    private ?CertificateVerifyProcessor $certificateVerifyProcessor = null;
    private ?FinishedProcessor $finishedProcessor = null;
    private ?KeyUpdateProcessor $keyUpdateProcessor = null;

    public function __construct(ProcessorFactory $factory)
    {
        $this->factory = $factory;
    }

    public function processClientHello(ClientHello $message): void
    {
        if (!$this->clientHelloProcessor) {
            $this->clientHelloProcessor = $this->factory->createClientHelloProcessor();
        }
        $this->clientHelloProcessor->process($message);
    }

    public function processServerHello(ServerHello $message): void
    {
        if (!$this->serverHelloProcessor) {
            $this->serverHelloProcessor = $this->factory->createServerHelloProcessor();
        }
        $this->serverHelloProcessor->process($message);
    }

    public function processEncryptedExtensions(EncryptedExtensions $message): void
    {
        if (!$this->encryptedExtensionsProcessor) {
            $this->encryptedExtensionsProcessor = $this->factory->createEncryptedExtensionsProcessor();
        }
        $this->encryptedExtensionsProcessor->process($message);
    }

    public function processCertificate(Certificate $message): void
    {
        if (!$this->certificateProcessor) {
            $this->certificateProcessor = $this->factory->createCertificateProcessor();
        }
        $this->certificateProcessor->process($message);
    }

    public function processCertificateVerify(CertificateVerify $message): void
    {
        if (!$this->certificateVerifyProcessor) {
            $this->certificateVerifyProcessor = $this->factory->createCertificateVerifyProcessor();
        }
        $this->certificateVerifyProcessor->process($message);
    }

    public function processFinished(Finished $message): void
    {
        if (!$this->finishedProcessor) {
            $this->finishedProcessor = $this->factory->createFinishedProcessor();
        }
        $this->finishedProcessor->process($message);
    }

    public function processKeyUpdate(KeyUpdate $message): void
    {
        if (!$this->keyUpdateProcessor) {
            $this->keyUpdateProcessor = $this->factory->createKeyUpdateProcessor();
        }
        $this->keyUpdateProcessor->process($message);
    }

    /**
     * Process message dynamically based on its type
     */
    public function processMessage(Message $message): void
    {
        match (get_class($message)) {
            ClientHello::class => $this->processClientHello($message),
            ServerHello::class => $this->processServerHello($message),
            EncryptedExtensions::class => $this->processEncryptedExtensions($message),
            Certificate::class => $this->processCertificate($message),
            CertificateVerify::class => $this->processCertificateVerify($message),
            Finished::class => $this->processFinished($message),
            KeyUpdate::class => $this->processKeyUpdate($message),
            default => throw new \InvalidArgumentException("No processor available for message type: " . get_class($message))
        };
    }
}
