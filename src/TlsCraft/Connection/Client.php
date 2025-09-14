<?php

namespace Php\TlsCraft\Connection;

use Php\TlsCraft\Control\FlowController;
use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Crypto\RandomGenerator;
use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Handshake\ClientHello;
use Php\TlsCraft\Handshake\Extension;
use Php\TlsCraft\Handshake\Finished;
use Php\TlsCraft\Handshake\HandshakeMessage;
use Php\TlsCraft\Protocol\ContentType;
use Php\TlsCraft\Protocol\HandshakeType;
use Php\TlsCraft\Protocol\Version;
use Php\TlsCraft\Record\Builder;
use Php\TlsCraft\State\Manager;

class Client
{
    private string $hostname;
    private int $port;
    private Manager $stateManager;
    private FlowController $controller;

    public function __construct(
        string $hostname,
        int $port,
        ?FlowController $controller = null
    ) {
        $this->hostname = $hostname;
        $this->port = $port;
        $this->stateManager = new Manager(true);
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

    public function connect(float $timeout = 30.0): ControlledConnection
    {
        // Establish TCP connection
        $socket = Socket::connect($this->hostname, $this->port, $timeout);

        // Create controlled connection
        $connection = new ControlledConnection($socket, $this->stateManager, $this->controller);

        // Start TLS handshake
        $this->stateManager->startHandshake();
        $this->performClientHandshake($connection);

        return $connection;
    }

    private function performClientHandshake(ControlledConnection $connection): void
    {
        $context = $this->stateManager->getHandshakeContext();

        // Generate client key pair for ECDH
        $context->generateKeyPair();

        // Create ClientHello with proper extensions
        $extensions = $this->createClientExtensions();

        $clientHello = new ClientHello(
            Version::TLS_1_2, // Legacy version field
            RandomGenerator::generateClientRandom(),
            '', // Empty session ID for TLS 1.3
            [CipherSuite::TLS_AES_128_GCM_SHA256->value],
            [0], // Null compression
            $extensions
        );

        // Process message and send
        $this->stateManager->processHandshakeMessage($clientHello);
        $record = Builder::handshake($clientHello->toWire());
        $connection->recordLayer->sendRecord($record);

        // Process server handshake messages
        $this->processServerHandshakeMessages($connection);

        // Send client Finished
        $this->sendClientFinished($connection);
    }

    private function createClientExtensions(): array
    {
        $extensions = [];

        // Supported versions (TLS 1.3)
        $versionsData = "\x02" . Version::TLS_1_3->toBytes();
        $extensions[] = new Extension(43, $versionsData);

        // Key share (simplified)
        $keyShareData = "\x00\x26" . // key_share length
                       "\x00\x17" . // secp256r1 group
                       "\x00\x20" . // key length (32 bytes)
                       str_repeat("\x01", 32); // placeholder public key
        $extensions[] = new Extension(51, $keyShareData);

        // SNI if hostname provided
        if ($this->hostname) {
            $sniData = pack('n', strlen($this->hostname) + 5) .
                      "\x00" .
                      pack('n', strlen($this->hostname)) .
                      $this->hostname;
            $extensions[] = new Extension(0, $sniData);
        }

        return $extensions;
    }

    private function processServerHandshakeMessages(ControlledConnection $connection): void
    {
        $expectedMessages = [
            HandshakeType::SERVER_HELLO,
            HandshakeType::ENCRYPTED_EXTENSIONS,
            HandshakeType::CERTIFICATE,
            HandshakeType::CERTIFICATE_VERIFY,
            HandshakeType::FINISHED
        ];

        $receivedCount = 0;

        while ($receivedCount < count($expectedMessages)) {
            $record = $connection->recordLayer->receiveRecord();
            if (!$record) {
                throw new CraftException("Connection closed during handshake");
            }

            if ($record->contentType === ContentType::HANDSHAKE) {
                try {
                    $offset = 0;
                    $message = HandshakeMessage::fromWire($record->payload, $offset);
                    $this->stateManager->processHandshakeMessage($message);
                    $receivedCount++;
                } catch (CraftException $e) {
                    $this->stateManager->error("handshake_parse_error: " . $e->getMessage());
                    throw $e;
                }
            }
        }
    }

    private function sendClientFinished(ControlledConnection $connection): void
    {
        $context = $this->stateManager->getHandshakeContext();

        $finishedData = $context->getFinishedData(true); // true = client
        $finished = new Finished($finishedData);

        $this->stateManager->processHandshakeMessage($finished);
        $record = Builder::handshake($finished->toWire());
        $connection->recordLayer->sendRecord($record);
    }
}