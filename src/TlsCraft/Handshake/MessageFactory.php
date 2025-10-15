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

    private function getClientHelloFactory(): ClientHelloFactory
    {
        if (!$this->clientHelloFactory) {
            $this->clientHelloFactory = new ClientHelloFactory($this->context, $this->config);
        }
        return $this->clientHelloFactory;
    }

    private function getServerHelloFactory(): ServerHelloFactory
    {
        if (!$this->serverHelloFactory) {
            $this->serverHelloFactory = new ServerHelloFactory($this->context, $this->config);
        }
        return $this->serverHelloFactory;
    }

    private function getEncryptedExtensionsFactory(): EncryptedExtensionsFactory
    {
        if (!$this->encryptedExtensionsFactory) {
            $this->encryptedExtensionsFactory = new EncryptedExtensionsFactory($this->context, $this->config);
        }
        return $this->encryptedExtensionsFactory;
    }

    private function getCertificateFactory(): CertificateFactory
    {
        if (!$this->certificateFactory) {
            $this->certificateFactory = new CertificateFactory($this->context, $this->config);
        }
        return $this->certificateFactory;
    }

    private function getCertificateVerifyFactory(): CertificateVerifyFactory
    {
        if (!$this->certificateVerifyFactory) {
            $this->certificateVerifyFactory = new CertificateVerifyFactory($this->context, $this->config);
        }
        return $this->certificateVerifyFactory;
    }

    private function getFinishedFactory(): FinishedFactory
    {
        if (!$this->finishedFactory) {
            $this->finishedFactory = new FinishedFactory($this->context, $this->config);
        }
        return $this->finishedFactory;
    }

    private function getKeyUpdateFactory(): KeyUpdateFactory
    {
        if (!$this->keyUpdateFactory) {
            $this->keyUpdateFactory = new KeyUpdateFactory($this->context, $this->config);
        }
        return $this->keyUpdateFactory;
    }

    public function createClientHello(): ClientHello
    {
        return $this->getClientHelloFactory()->create();
    }

    public function createServerHello(): ServerHello
    {
        return $this->getServerHelloFactory()->create();
    }

    public function createEncryptedExtensions(): EncryptedExtensions
    {
        return $this->getEncryptedExtensionsFactory()->create();
    }

    public function createCertificate(array $certificateChain): Certificate
    {
        return $this->getCertificateFactory()->create($certificateChain);
    }

    public function createCertificateVerify(string $signature): CertificateVerify
    {
        return $this->getCertificateVerifyFactory()->create($signature);
    }

    public function createFinished(bool $isClient): Finished
    {
        return $this->getFinishedFactory()->create($isClient);
    }

    public function createKeyUpdate(bool $requestUpdate): KeyUpdate
    {
        return $this->getKeyUpdateFactory()->create($requestUpdate);
    }

    public function createAlert(AlertLevel $level, AlertDescription $description): string
    {
        return $level->toByte().$description->toByte();
    }

    // FromWire methods
    public function createClientHelloFromWire(string $data, int &$offset = 0): ClientHello
    {
        return $this->getClientHelloFactory()->fromWire($data, $offset);
    }

    public function createServerHelloFromWire(string $data, int &$offset = 0): ServerHello
    {
        return $this->getServerHelloFactory()->fromWire($data, $offset);
    }

    public function createEncryptedExtensionsFromWire(string $data, int &$offset = 0): EncryptedExtensions
    {
        return $this->getEncryptedExtensionsFactory()->fromWire($data, $offset);
    }

    public function createCertificateFromWire(string $data, int &$offset = 0): Certificate
    {
        return $this->getCertificateFactory()->fromWire($data, $offset);
    }

    public function createCertificateVerifyFromWire(string $data, int &$offset = 0): CertificateVerify
    {
        return $this->getCertificateVerifyFactory()->fromWire($data, $offset);
    }

    public function createFinishedFromWire(string $data, int &$offset = 0): Finished
    {
        return $this->getFinishedFactory()->fromWire($data, $offset);
    }

    public function createKeyUpdateFromWire(string $data, int &$offset = 0): KeyUpdate
    {
        return $this->getKeyUpdateFactory()->fromWire($data, $offset);
    }
}
