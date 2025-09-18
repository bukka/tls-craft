<?php

namespace Php\TlsCraft\Handshake;

use Php\TlsCraft\Config;
use Php\TlsCraft\Context;
use Php\TlsCraft\Handshake\MessageFactories\{
    CertificateFactory,
    CertificateVerifyFactory,
    ClientHelloFactory,
    EncryptedExtensionsFactory,
    FinishedFactory,
    KeyUpdateFactory,
    ServerHelloFactory
};
use Php\TlsCraft\Handshake\Messages\Certificate;
use Php\TlsCraft\Handshake\Messages\CertificateVerify;
use Php\TlsCraft\Handshake\Messages\ClientHello;
use Php\TlsCraft\Handshake\Messages\EncryptedExtensions;
use Php\TlsCraft\Handshake\Messages\Finished;
use Php\TlsCraft\Handshake\Messages\KeyUpdate;
use Php\TlsCraft\Handshake\Messages\ServerHello;
use Php\TlsCraft\Protocol\{AlertDescription, AlertLevel};

class MessageFactory
{
    private Config $config;

    // Cached factory instances
    private ?ClientHelloFactory $clientHelloFactory = null;
    private ?ServerHelloFactory $serverHelloFactory = null;
    private ?EncryptedExtensionsFactory $encryptedExtensionsFactory = null;
    private ?CertificateFactory $certificateFactory = null;
    private ?CertificateVerifyFactory $certificateVerifyFactory = null;
    private ?FinishedFactory $finishedFactory = null;
    private ?KeyUpdateFactory $keyUpdateFactory = null;

    public function __construct(private Context $context)
    {
        $this->config = $context->getConfig();
    }

    public function createClientHello(): ClientHello
    {
        if (!$this->clientHelloFactory) {
            $this->clientHelloFactory = new ClientHelloFactory($this->context, $this->config);
        }

        return $this->clientHelloFactory->create();
    }

    public function createServerHello(): ServerHello
    {
        if (!$this->serverHelloFactory) {
            $this->serverHelloFactory = new ServerHelloFactory($this->context, $this->config);
        }

        return $this->serverHelloFactory->create();
    }

    public function createEncryptedExtensions(): EncryptedExtensions
    {
        if (!$this->encryptedExtensionsFactory) {
            $this->encryptedExtensionsFactory = new EncryptedExtensionsFactory($this->context, $this->config);
        }

        return $this->encryptedExtensionsFactory->create();
    }

    public function createCertificate(array $certificateChain): Certificate
    {
        if (!$this->certificateFactory) {
            $this->certificateFactory = new CertificateFactory($this->context, $this->config);
        }

        return $this->certificateFactory->create($certificateChain);
    }

    public function createCertificateVerify(string $signature): CertificateVerify
    {
        if (!$this->certificateVerifyFactory) {
            $this->certificateVerifyFactory = new CertificateVerifyFactory($this->context, $this->config);
        }

        return $this->certificateVerifyFactory->create($signature);
    }

    public function createFinished(bool $isClient): Finished
    {
        if (!$this->finishedFactory) {
            $this->finishedFactory = new FinishedFactory($this->context, $this->config);
        }

        return $this->finishedFactory->create($isClient);
    }

    public function createKeyUpdate(bool $requestUpdate): KeyUpdate
    {
        if (!$this->keyUpdateFactory) {
            $this->keyUpdateFactory = new KeyUpdateFactory($this->context, $this->config);
        }

        return $this->keyUpdateFactory->create($requestUpdate);
    }

    public function createAlert(AlertLevel $level, AlertDescription $description): string
    {
        return $level->toByte().$description->toByte();
    }
}
