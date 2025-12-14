<?php

namespace Php\TlsCraft\Handshake;

use Php\TlsCraft\Config;
use Php\TlsCraft\Context;
use Php\TlsCraft\Crypto\CertificateChain;
use Php\TlsCraft\Handshake\MessageFactories\{CertificateFactory,
    CertificateRequestFactory,
    CertificateVerifyFactory,
    ClientHelloFactory,
    EncryptedExtensionsFactory,
    FinishedFactory,
    KeyUpdateFactory,
    ServerHelloFactory};
use Php\TlsCraft\Handshake\MessageParsers\CertificateParser;
use Php\TlsCraft\Handshake\MessageParsers\CertificateRequestParser;
use Php\TlsCraft\Handshake\MessageParsers\CertificateVerifyParser;
use Php\TlsCraft\Handshake\MessageParsers\ClientHelloParser;
use Php\TlsCraft\Handshake\MessageParsers\EncryptedExtensionsParser;
use Php\TlsCraft\Handshake\MessageParsers\FinishedParser;
use Php\TlsCraft\Handshake\MessageParsers\KeyUpdateParser;
use Php\TlsCraft\Handshake\MessageParsers\ServerHelloParser;
use Php\TlsCraft\Handshake\Messages\CertificateMessage;
use Php\TlsCraft\Handshake\Messages\CertificateRequestMessage;
use Php\TlsCraft\Handshake\Messages\CertificateVerifyMessage;
use Php\TlsCraft\Handshake\Messages\ClientHelloMessage;
use Php\TlsCraft\Handshake\Messages\EncryptedExtensionsMessage;
use Php\TlsCraft\Handshake\Messages\FinishedMessage;
use Php\TlsCraft\Handshake\Messages\KeyUpdateMessage;
use Php\TlsCraft\Handshake\Messages\ServerHelloMessage;
use Php\TlsCraft\Protocol\{AlertDescription, AlertLevel};

class MessageFactory
{
    private Config $config;

    // Cached factory instances
    private ?ClientHelloFactory $clientHelloFactory = null;
    private ?ServerHelloFactory $serverHelloFactory = null;
    private ?EncryptedExtensionsFactory $encryptedExtensionsFactory = null;
    private ?CertificateFactory $certificateFactory = null;
    private ?CertificateRequestFactory $certificateRequestFactory = null;
    private ?CertificateVerifyFactory $certificateVerifyFactory = null;
    private ?FinishedFactory $finishedFactory = null;
    private ?KeyUpdateFactory $keyUpdateFactory = null;

    private ?ClientHelloParser $clientHelloParser = null;
    private ?ServerHelloParser $serverHelloParser = null;
    private ?EncryptedExtensionsParser $encryptedExtensionsParser = null;
    private ?CertificateParser $certificateParser = null;
    private ?CertificateRequestParser $certificateRequestParser = null;
    private ?CertificateVerifyParser $certificateVerifyParser = null;
    private ?FinishedParser $finishedParser = null;
    private ?KeyUpdateParser $keyUpdateParser = null;

    public function __construct(private Context $context, private ExtensionFactory $extensionFactory)
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

    private function getCertificateRequestFactory(): CertificateRequestFactory
    {
        if (!$this->certificateRequestFactory) {
            $this->certificateRequestFactory = new CertificateRequestFactory($this->context, $this->config);
        }

        return $this->certificateRequestFactory;
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

    private function getClientHelloParser(): ClientHelloParser
    {
        if (!$this->clientHelloParser) {
            $this->clientHelloParser = new ClientHelloParser($this->context, $this->extensionFactory);
        }

        return $this->clientHelloParser;
    }

    private function getServerHelloParser(): ServerHelloParser
    {
        if (!$this->serverHelloParser) {
            $this->serverHelloParser = new ServerHelloParser($this->context, $this->extensionFactory);
        }

        return $this->serverHelloParser;
    }

    private function getEncryptedExtensionsParser(): EncryptedExtensionsParser
    {
        if (!$this->encryptedExtensionsParser) {
            $this->encryptedExtensionsParser = new EncryptedExtensionsParser($this->context, $this->extensionFactory);
        }

        return $this->encryptedExtensionsParser;
    }

    private function getCertificateParser(): CertificateParser
    {
        if (!$this->certificateParser) {
            $this->certificateParser = new CertificateParser($this->context, $this->extensionFactory);
        }

        return $this->certificateParser;
    }

    private function getCertificateRequestParser(): CertificateRequestParser
    {
        if (!$this->certificateRequestParser) {
            $this->certificateRequestParser = new CertificateRequestParser($this->context, $this->extensionFactory);
        }

        return $this->certificateRequestParser;
    }

    private function getCertificateVerifyParser(): CertificateVerifyParser
    {
        if (!$this->certificateVerifyParser) {
            $this->certificateVerifyParser = new CertificateVerifyParser($this->context, $this->extensionFactory);
        }

        return $this->certificateVerifyParser;
    }

    private function getFinishedParser(): FinishedParser
    {
        if (!$this->finishedParser) {
            $this->finishedParser = new FinishedParser($this->context, $this->extensionFactory);
        }

        return $this->finishedParser;
    }

    private function getKeyUpdateParser(): KeyUpdateParser
    {
        if (!$this->keyUpdateParser) {
            $this->keyUpdateParser = new KeyUpdateParser($this->context, $this->extensionFactory);
        }

        return $this->keyUpdateParser;
    }

    public function createClientHello(): ClientHelloMessage
    {
        return $this->getClientHelloFactory()->create();
    }

    public function createServerHello(): ServerHelloMessage
    {
        return $this->getServerHelloFactory()->create();
    }

    public function createEncryptedExtensions(): EncryptedExtensionsMessage
    {
        return $this->getEncryptedExtensionsFactory()->create();
    }

    public function createCertificate(CertificateChain $certificateChain): CertificateMessage
    {
        return $this->getCertificateFactory()->create($certificateChain);
    }

    public function createCertificateRequest(): CertificateRequestMessage
    {
        return $this->getCertificateRequestFactory()->create();
    }

    public function createCertificateVerify(string $signature): CertificateVerifyMessage
    {
        return $this->getCertificateVerifyFactory()->create($signature);
    }

    public function createFinished(bool $isClient): FinishedMessage
    {
        return $this->getFinishedFactory()->create($isClient);
    }

    public function createKeyUpdate(bool $requestUpdate): KeyUpdateMessage
    {
        return $this->getKeyUpdateFactory()->create($requestUpdate);
    }

    public function createAlert(AlertLevel $level, AlertDescription $description): string
    {
        return $level->toByte().$description->toByte();
    }

    // FromWire methods
    public function createClientHelloFromWire(string $data, int &$offset = 0): ClientHelloMessage
    {
        return $this->getClientHelloParser()->parse($data, $offset);
    }

    public function createServerHelloFromWire(string $data, int &$offset = 0): ServerHelloMessage
    {
        return $this->getServerHelloParser()->parse($data, $offset);
    }

    public function createEncryptedExtensionsFromWire(string $data, int &$offset = 0): EncryptedExtensionsMessage
    {
        return $this->getEncryptedExtensionsParser()->parse($data, $offset);
    }

    public function createCertificateFromWire(string $data, int &$offset = 0): CertificateMessage
    {
        return $this->getCertificateParser()->parse($data, $offset);
    }

    public function createCertificateRequestFromWire(string $data, int &$offset = 0): CertificateRequestMessage
    {
        return $this->getCertificateRequestParser()->parse($data, $offset);
    }

    public function createCertificateVerifyFromWire(string $data, int &$offset = 0): CertificateVerifyMessage
    {
        return $this->getCertificateVerifyParser()->parse($data, $offset);
    }

    public function createFinishedFromWire(string $data, int &$offset = 0): FinishedMessage
    {
        return $this->getFinishedParser()->parse($data, $offset);
    }

    public function createKeyUpdateFromWire(string $data, int &$offset = 0): KeyUpdateMessage
    {
        return $this->getKeyUpdateParser()->parse($data, $offset);
    }
}
