<?php

namespace Php\TlsCraft\Connection;

use Php\TlsCraft\Control\FlowController;
use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Crypto\RandomGenerator;
use Php\TlsCraft\Crypto\SignatureScheme;
use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Handshake\Certificate;
use Php\TlsCraft\Handshake\CertificateVerify;
use Php\TlsCraft\Handshake\EncryptedExtensions;
use Php\TlsCraft\Handshake\Extension;
use Php\TlsCraft\Handshake\Finished;
use Php\TlsCraft\Handshake\ServerHello;
use Php\TlsCraft\Protocol\ContentType;
use Php\TlsCraft\Protocol\Version;
use Php\TlsCraft\Record\Builder;
use Php\TlsCraft\State\HandshakeState;
use Php\TlsCraft\State\Manager;

class Server
{
    private string $certificatePath;
    private string $privateKeyPath;
    private Manager $stateManager;
    private FlowController $controller;
    private ?Socket $serverSocket = null;

    public function __construct(
        string          $certificatePath,
        string          $privateKeyPath,
        ?FlowController $controller = null
    )
    {
        $this->certificatePath = $certificatePath;
        $this->privateKeyPath = $privateKeyPath;
        $this->stateManager = new Manager(false);
        $this->controller = $controller ?? new FlowController($this->stateManager);
    }

    public function getStateManager(): Manager
    {
        return $this->stateManager;
    }

    public function getController(): FlowController
    {
        return $this->controller;
    }

    public function listen(string $address, int $port): void
    {
        $this->serverSocket = Socket::server($address, $port);
    }

    public function accept(float $timeout = null): ControlledConnection
    {
        if (!$this->serverSocket) {
            throw new CraftException("Server not listening");
        }

        // Accept TCP connection
        $clientSocket = $this->serverSocket->accept($timeout);

        // Create new state manager for this connection
        $connectionStateManager = new Manager(false);
        $connectionController = new FlowController($connectionStateManager);

        // Create controlled connection
        $connection = new ControlledConnection(
            $clientSocket,
            $connectionStateManager,
            $connectionController
        );

        // Start TLS handshake
        $connectionStateManager->startHandshake();
        $this->performServerHandshake($connection);

        return $connection;
    }

    public function getAddress(): string
    {
        return $this->serverSocket ? $this->serverSocket->getLocalName() : '';
    }

    public function close(): void
    {
        $this->serverSocket?->close();
    }

    private function performServerHandshake(ControlledConnection $connection): void
    {
        $stateManager = $connection->getStateManager();
        $context = $stateManager->getHandshakeContext();

        // Wait for ClientHello
        $this->waitForClientHello($connection);

        // Generate server key pair
        $context->generateKeyPair();

        // Send server handshake flight
        $this->sendServerHandshakeFlight($connection);

        // Wait for client Finished
        $this->waitForClientFinished($connection);
    }

    private function waitForClientHello(ControlledConnection $connection): void
    {
        $stateManager = $connection->getStateManager();

        while ($stateManager->getHandshakeState() === HandshakeState::WAIT_CLIENT_HELLO) {
            $record = $connection->recordLayer->receiveRecord();
            if (!$record) {
                throw new CraftException("Connection closed waiting for ClientHello");
            }

            if ($record->contentType === ContentType::HANDSHAKE) {
                $connection->handleNonApplicationRecord($record);
            }
        }
    }

    private function sendServerHandshakeFlight(ControlledConnection $connection): void
    {
        $stateManager = $connection->getStateManager();
        $context = $stateManager->getHandshakeContext();

        // 1. ServerHello
        $this->sendServerHello($connection);

        // 2. EncryptedExtensions
        $this->sendEncryptedExtensions($connection);

        // 3. Certificate
        $this->sendCertificate($connection);

        // 4. CertificateVerify
        $this->sendCertificateVerify($connection);

        // 5. Finished
        $this->sendServerFinished($connection);
    }

    private function sendServerHello(ControlledConnection $connection): void
    {
        $stateManager = $connection->getStateManager();

        $extensions = [];

        // Supported versions
        $versionsData = "\x02" . Version::TLS_1_3->toBytes();
        $extensions[] = new Extension(43, $versionsData);

        // Key share (simplified)
        $keyShareData = "\x00\x17" . // secp256r1 group
            "\x00\x20" . // key length
            str_repeat("\x02", 32); // placeholder server public key
        $extensions[] = new Extension(51, $keyShareData);

        $serverHello = new ServerHello(
            Version::TLS_1_2, // Legacy field
            RandomGenerator::generateServerRandom(),
            '', // Empty session ID
            CipherSuite::TLS_AES_128_GCM_SHA256->value,
            0, // Null compression
            $extensions
        );

        $stateManager->processHandshakeMessage($serverHello);
        $record = Builder::handshake($serverHello->toWire());
        $connection->recordLayer->sendRecord($record);
    }

    private function sendEncryptedExtensions(ControlledConnection $connection): void
    {
        $stateManager = $connection->getStateManager();

        $encExtensions = new EncryptedExtensions([]);
        $stateManager->processHandshakeMessage($encExtensions);
        $record = Builder::handshake($encExtensions->toWire());
        $connection->recordLayer->sendRecord($record);
    }

    private function sendCertificate(ControlledConnection $connection): void
    {
        $stateManager = $connection->getStateManager();

        $certData = $this->loadCertificate();
        $certificate = new Certificate('', [$certData]);
        $stateManager->processHandshakeMessage($certificate);
        $record = Builder::handshake($certificate->toWire());
        $connection->recordLayer->sendRecord($record);
    }

    private function sendCertificateVerify(ControlledConnection $connection): void
    {
        $stateManager = $connection->getStateManager();
        $context = $stateManager->getHandshakeContext();

        $signature = $this->createCertificateVerifySignature($context);
        $certVerify = new CertificateVerify(
            SignatureScheme::RSA_PKCS1_SHA256->value,
            $signature
        );
        $stateManager->processHandshakeMessage($certVerify);
        $record = Builder::handshake($certVerify->toWire());
        $connection->recordLayer->sendRecord($record);
    }

    private function sendServerFinished(ControlledConnection $connection): void
    {
        $stateManager = $connection->getStateManager();
        $context = $stateManager->getHandshakeContext();

        $finishedData = $context->getFinishedData(false); // false = server
        $finished = new Finished($finishedData);
        $stateManager->processHandshakeMessage($finished);
        $record = Builder::handshake($finished->toWire());
        $connection->recordLayer->sendRecord($record);
    }

    private function waitForClientFinished(ControlledConnection $connection): void
    {
        $stateManager = $connection->getStateManager();

        while (!$stateManager->isHandshakeComplete()) {
            $record = $connection->recordLayer->receiveRecord();
            if (!$record) {
                throw new CraftException("Connection closed waiting for client Finished");
            }

            if ($record->contentType === ContentType::HANDSHAKE) {
                $connection->handleNonApplicationRecord($record);
            }
        }
    }

    private function loadCertificate(): string
    {
        if (!file_exists($this->certificatePath)) {
            throw new CraftException("Certificate file not found: {$this->certificatePath}");
        }

        $certData = file_get_contents($this->certificatePath);
        if ($certData === false) {
            throw new CraftException("Failed to read certificate file");
        }

        // Convert PEM to DER if needed
        if (strpos($certData, '-----BEGIN CERTIFICATE-----') !== false) {
            $cert = openssl_x509_read($certData);
            if ($cert === false) {
                throw new CraftException("Invalid certificate format");
            }
            openssl_x509_export($cert, $certData, false);
        }

        return $certData;
    }

    private function createCertificateVerifySignature(\Php\TlsCraft\Handshake\Context $context): string
    {
        $transcript = $context->getHandshakeTranscript();
        $signatureContext = str_repeat("\x20", 64) .
            "TLS 1.3, server CertificateVerify" .
            "\x00" .
            hash('sha256', $transcript, true);

        // Placeholder signature - in practice would use private key
        return str_repeat("\x00", 256);
    }
}
