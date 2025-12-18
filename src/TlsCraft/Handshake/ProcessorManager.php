<?php

namespace Php\TlsCraft\Handshake;

use InvalidArgumentException;
use Php\TlsCraft\Handshake\Messages\CertificateMessage;
use Php\TlsCraft\Handshake\Messages\CertificateRequestMessage;
use Php\TlsCraft\Handshake\Messages\CertificateVerifyMessage;
use Php\TlsCraft\Handshake\Messages\ClientHelloMessage;
use Php\TlsCraft\Handshake\Messages\EncryptedExtensionsMessage;
use Php\TlsCraft\Handshake\Messages\FinishedMessage;
use Php\TlsCraft\Handshake\Messages\KeyUpdateMessage;
use Php\TlsCraft\Handshake\Messages\Message;
use Php\TlsCraft\Handshake\Messages\NewSessionTicketMessage;
use Php\TlsCraft\Handshake\Messages\ServerHelloMessage;
use Php\TlsCraft\Handshake\Processors\{CertificateProcessor,
    CertificateRequestProcessor,
    CertificateVerifyProcessor,
    ClientHelloProcessor,
    EncryptedExtensionsProcessor,
    FinishedProcessor,
    KeyUpdateProcessor,
    NewSessionTicketProcessor,
    ServerHelloProcessor};

class ProcessorManager
{
    private ProcessorFactory $factory;

    // Cached processor instances
    private ?ClientHelloProcessor $clientHelloProcessor = null;
    private ?ServerHelloProcessor $serverHelloProcessor = null;
    private ?EncryptedExtensionsProcessor $encryptedExtensionsProcessor = null;
    private ?CertificateProcessor $certificateProcessor = null;
    private ?CertificateRequestProcessor $certificateRequestProcessor = null;
    private ?CertificateVerifyProcessor $certificateVerifyProcessor = null;
    private ?FinishedProcessor $finishedProcessor = null;
    private ?NewSessionTicketProcessor $newSessionTicketProcessor = null;
    private ?KeyUpdateProcessor $keyUpdateProcessor = null;

    public function __construct(ProcessorFactory $factory)
    {
        $this->factory = $factory;
    }

    public function processClientHello(ClientHelloMessage $message): void
    {
        if (!$this->clientHelloProcessor) {
            $this->clientHelloProcessor = $this->factory->createClientHelloProcessor();
        }
        $this->clientHelloProcessor->process($message);
    }

    public function processServerHello(ServerHelloMessage $message): void
    {
        if (!$this->serverHelloProcessor) {
            $this->serverHelloProcessor = $this->factory->createServerHelloProcessor();
        }
        $this->serverHelloProcessor->process($message);
    }

    public function processEncryptedExtensions(EncryptedExtensionsMessage $message): void
    {
        if (!$this->encryptedExtensionsProcessor) {
            $this->encryptedExtensionsProcessor = $this->factory->createEncryptedExtensionsProcessor();
        }
        $this->encryptedExtensionsProcessor->process($message);
    }

    public function processCertificate(CertificateMessage $message): void
    {
        if (!$this->certificateProcessor) {
            $this->certificateProcessor = $this->factory->createCertificateProcessor();
        }
        $this->certificateProcessor->process($message);
    }

    public function processCertificateRequest(CertificateRequestMessage $message): void
    {
        if (!$this->certificateRequestProcessor) {
            $this->certificateRequestProcessor = $this->factory->createCertificateRequestProcessor();
        }
        $this->certificateRequestProcessor->process($message);
    }

    public function processCertificateVerify(CertificateVerifyMessage $message): void
    {
        if (!$this->certificateVerifyProcessor) {
            $this->certificateVerifyProcessor = $this->factory->createCertificateVerifyProcessor();
        }
        $this->certificateVerifyProcessor->process($message);
    }

    public function processFinished(FinishedMessage $message): void
    {
        if (!$this->finishedProcessor) {
            $this->finishedProcessor = $this->factory->createFinishedProcessor();
        }
        $this->finishedProcessor->process($message);
    }

    public function processNewSessionTicket(NewSessionTicketMessage $message): void
    {
        if (!$this->newSessionTicketProcessor) {
            $this->newSessionTicketProcessor = $this->factory->createNewSessionTicketProcessor();
        }
        $this->newSessionTicketProcessor->process($message);
    }

    public function processKeyUpdate(KeyUpdateMessage $message): void
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
        match ($message::class) {
            ClientHelloMessage::class => $this->processClientHello($message),
            ServerHelloMessage::class => $this->processServerHello($message),
            EncryptedExtensionsMessage::class => $this->processEncryptedExtensions($message),
            CertificateMessage::class => $this->processCertificate($message),
            CertificateRequestMessage::class => $this->processCertificateRequest($message),
            CertificateVerifyMessage::class => $this->processCertificateVerify($message),
            FinishedMessage::class => $this->processFinished($message),
            NewSessionTicketMessage::class => $this->processNewSessionTicket($message),
            KeyUpdateMessage::class => $this->processKeyUpdate($message),
            default => throw new InvalidArgumentException('No processor available for message type: '.$message::class),
        };
    }
}
