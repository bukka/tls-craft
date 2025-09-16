<?php

namespace Php\TlsCraft\Protocol;

use Php\TlsCraft\Connection\Connection;
use Php\TlsCraft\Context;
use Php\TlsCraft\Control\{FlowController};
use Php\TlsCraft\Crypto\CertificateUtils;
use Php\TlsCraft\Exceptions\{CraftException, ProtocolViolationException};
use Php\TlsCraft\Messages\{Certificate,
    CertificateVerify,
    ClientHello,
    EncryptedExtensions,
    Finished,
    KeyUpdate,
    Message,
    MessageFactory,
    ProcessorManager,
    ServerHello};
use Php\TlsCraft\Record\{Builder, EncryptedLayer, LayerFactory, Record};
use Php\TlsCraft\State\{HandshakeState, ProtocolValidator, StateTracker};

/**
 * Updated ProtocolOrchestrator with clean typing and proper integration
 */
class ProtocolOrchestrator
{
    private StateTracker $stateTracker;
    private ProtocolValidator $validator;
    private Context $context;
    private ProcessorManager $processorManager;
    private MessageFactory $messageFactory;
    private EncryptedLayer $recordLayer;
    private ?FlowController $flowController;
    private Connection $connection;

    public function __construct(
        StateTracker      $stateTracker,
        ProtocolValidator $validator,
        Context           $context,
        ProcessorManager  $processorManager,
        LayerFactory      $layerFactory,
        MessageFactory    $messageFactory,
        Connection        $connection,
        ?FlowController   $flowController,
    )
    {
        $this->stateTracker = $stateTracker;
        $this->validator = $validator;
        $this->context = $context;
        $this->processorManager = $processorManager;
        $this->messageFactory = $messageFactory;
        $this->connection = $connection;
        $this->flowController = $flowController;
        $this->recordLayer = $layerFactory->createEncryptedLayer($connection, $context, $this->flowController);
    }

    public function isConnected(): bool
    {
        return $this->stateTracker->isConnected() && $this->connection->isConnected();
    }

    public function getStateTracker(): StateTracker
    {
        return $this->stateTracker;
    }

    // === Handshake Operations ===

    public function performClientHandshake(): void
    {
        $this->stateTracker->startHandshake();

        // Send ClientHello
        $clientHello = $this->messageFactory->createClientHello($this->context);
        $this->sendHandshakeMessage($clientHello);

        // Process server handshake messages
        $this->processServerHandshakeMessages();

        // Send client Finished
        $finished = $this->messageFactory->createFinished($this->context, true);
        $this->sendHandshakeMessage($finished);
    }

    public function performServerHandshake(): void
    {
        $this->stateTracker->startHandshake();

        // Wait for ClientHello
        $this->waitForClientHello();

        // Generate key pair
        $this->context->generateKeyPair();

        // Send server handshake flight
        $this->sendServerHandshakeFlight();

        // Wait for client Finished
        $this->waitForClientFinished();
    }

    // === Application Data Operations ===

    public function sendApplicationData(string $data): void
    {
        if (!$this->stateTracker->isConnected()) {
            throw new CraftException("Cannot send application data: not connected");
        }

        $record = Builder::applicationData($data);
        $this->recordLayer->sendRecord($record);
    }

    public function receiveApplicationData(): ?string
    {
        if (!$this->stateTracker->isConnected()) {
            throw new CraftException("Cannot receive application data: not connected");
        }

        $record = $this->recordLayer->receiveRecord();
        if (!$record) {
            return null;
        }

        if ($record->isApplicationData()) {
            return $record->payload;
        }

        // Handle non-application data records
        $this->handleNonApplicationRecord($record);
        return null;
    }

    // === Post-Handshake Operations ===

    public function sendKeyUpdate(bool $requestUpdate = false): void
    {
        if (!$this->stateTracker->isConnected()) {
            throw new CraftException("Cannot send KeyUpdate: not connected");
        }

        $keyUpdate = $this->messageFactory->createKeyUpdate($requestUpdate);
        $this->sendHandshakeMessage($keyUpdate);

        // Update our own keys
        $this->context->updateTrafficKeys();
    }

    public function sendAlert(AlertLevel $level, AlertDescription $description): void
    {
        $alertData = $this->messageFactory->createAlert($level, $description);
        $record = Builder::alert($alertData);
        $this->recordLayer->sendRecord($record);

        if ($description->isFatal()) {
            $this->stateTracker->error("sent_fatal_alert_{$description->name}");
        }
    }

    public function close(): void
    {
        if ($this->stateTracker->isConnected()) {
            $this->sendAlert(AlertLevel::WARNING, AlertDescription::CLOSE_NOTIFY);
        }
        $this->stateTracker->close(false);
    }

    public function abruptClose(): void
    {
        $this->stateTracker->close(true);
    }

    // === Internal Handshake Methods ===

    private function sendHandshakeMessage(Message $message, bool $encrypted = true): void
    {
        // Validate if enabled
        if (!$this->validator->validateHandshakeMessage(
            $message->type,
            $this->stateTracker->getHandshakeState(),
            $this->stateTracker->isClient()
        )) {
            throw new ProtocolViolationException(
                "Invalid handshake message {$message->type->name} in state {$this->stateTracker->getHandshakeState()->value}"
            );
        }

        // Add to context transcript
        $this->context->addHandshakeMessage($message);

        // Send record
        $record = Builder::handshake($message->toWire(), $encrypted);
        $this->recordLayer->sendRecord($record);
    }

    private function processServerHandshakeMessages(): void
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
            $record = $this->recordLayer->receiveRecord();
            if (!$record) {
                throw new CraftException("Connection closed during handshake");
            }

            if ($record->isHandshake()) {
                $this->processHandshakeRecord($record);
                $receivedCount++;
            }
        }
    }

    private function waitForClientHello(): void
    {
        while ($this->stateTracker->getHandshakeState() === HandshakeState::WAIT_CLIENT_HELLO) {
            $record = $this->recordLayer->receiveRecord();
            if (!$record) {
                throw new CraftException("Connection closed waiting for ClientHello");
            }

            if ($record->isHandshake()) {
                $this->processHandshakeRecord($record);
            }
        }
    }

    private function sendServerHandshakeFlight(): void
    {
        // 1. ServerHello
        $serverHello = $this->messageFactory->createServerHello($this->context);
        $this->sendHandshakeMessage($serverHello);

        // 2. EncryptedExtensions
        $encryptedExtensions = $this->messageFactory->createEncryptedExtensions($this->context);
        $this->sendHandshakeMessage($encryptedExtensions);

        // 3. Certificate
        $certificateChain = $this->context->getCertificateChain();
        $certificate = $this->messageFactory->createCertificate($this->context, $certificateChain);
        $this->sendHandshakeMessage($certificate);

        // 4. CertificateVerify
        $signature = $this->createCertificateVerifySignature();
        $certificateVerify = $this->messageFactory->createCertificateVerify($this->context, $signature);
        $this->sendHandshakeMessage($certificateVerify);

        // 5. Finished
        $finished = $this->messageFactory->createFinished($this->context, false);
        $this->sendHandshakeMessage($finished);
    }

    private function waitForClientFinished(): void
    {
        while (!$this->stateTracker->isHandshakeComplete()) {
            $record = $this->recordLayer->receiveRecord();
            if (!$record) {
                throw new CraftException("Connection closed waiting for client Finished");
            }

            if ($record->isHandshake()) {
                $this->processHandshakeRecord($record);
            }
        }
    }

    // === Enhanced Message Processing with Processors ===

    private function processHandshakeRecord(Record $record): void
    {
        try {
            $handshakeType = $record->getHandshakeType();

            // Validate message type for current state
            if (!$this->validator->validateHandshakeMessage(
                $handshakeType,
                $this->stateTracker->getHandshakeState(),
                $this->stateTracker->isClient()
            )) {
                throw new ProtocolViolationException(
                    "Unexpected handshake message {$handshakeType->name} in state {$this->stateTracker->getHandshakeState()->value}"
                );
            }

            // Parse to specific type and handle with processors
            switch ($handshakeType) {
                case HandshakeType::CLIENT_HELLO:
                    $clientHello = ClientHello::fromWire($record->payload);
                    $this->processorManager->processClientHello($clientHello);
                    $this->stateTracker->transitionHandshake(HandshakeState::WAIT_FLIGHT2);
                    break;

                case HandshakeType::SERVER_HELLO:
                    $serverHello = ServerHello::fromWire($record->payload);
                    $this->processorManager->processServerHello($serverHello);
                    $this->stateTracker->transitionHandshake(HandshakeState::WAIT_ENCRYPTED_EXTENSIONS);
                    break;

                case HandshakeType::ENCRYPTED_EXTENSIONS:
                    $encryptedExtensions = EncryptedExtensions::fromWire($record->payload);
                    $this->processorManager->processEncryptedExtensions($encryptedExtensions);
                    $this->stateTracker->transitionHandshake(HandshakeState::WAIT_CERTIFICATE);
                    break;

                case HandshakeType::CERTIFICATE:
                    $certificate = Certificate::fromWire($record->payload);
                    $this->processorManager->processCertificate($certificate);
                    $this->stateTracker->transitionHandshake(HandshakeState::WAIT_CERTIFICATE_VERIFY);
                    break;

                case HandshakeType::CERTIFICATE_VERIFY:
                    $certificateVerify = CertificateVerify::fromWire($record->payload);
                    $this->processorManager->processCertificateVerify($certificateVerify);
                    $this->stateTracker->transitionHandshake(HandshakeState::WAIT_FINISHED);
                    break;

                case HandshakeType::FINISHED:
                    $finished = Finished::fromWire($record->payload);
                    $this->processorManager->processFinished($finished);
                    $this->stateTracker->completeHandshake();
                    break;

                case HandshakeType::KEY_UPDATE:
                    $keyUpdate = KeyUpdate::fromWire($record->payload);
                    $this->processorManager->processKeyUpdate($keyUpdate);
                    // KeyUpdate doesn't change handshake state (post-handshake message)
                    break;

                default:
                    throw new ProtocolViolationException("Unsupported handshake message: {$handshakeType->name}");
            }

        } catch (CraftException $e) {
            $this->stateTracker->error("handshake_parse_error: " . $e->getMessage());
            throw $e;
        }
    }

    private function handleKeyUpdate(KeyUpdate $keyUpdate): void
    {
        if (!$this->stateTracker->isConnected()) {
            throw new ProtocolViolationException("KeyUpdate received before connection established");
        }

        // Update keys
        $this->context->updateTrafficKeys();

        // Send KeyUpdate response if requested
        if ($keyUpdate->requestUpdate) {
            $response = $this->messageFactory->createKeyUpdate(false);
            $this->sendHandshakeMessage($response);
        }
    }

    private function handleNonApplicationRecord(Record $record): void
    {
        if ($record->isHandshake()) {
            $this->processHandshakeRecord($record);
        } elseif ($record->isAlert()) {
            $this->handleAlertRecord($record);
        }
        // Ignore other types (e.g., ChangeCipherSpec for compatibility)
    }

    private function handleAlertRecord(Record $record): void
    {
        if (strlen($record->payload) >= 2) {
            $level = AlertLevel::fromByte($record->payload[0]);
            $description = AlertDescription::fromByte($record->payload[1]);

            if ($description === AlertDescription::CLOSE_NOTIFY) {
                $this->stateTracker->close(false);
            } elseif ($description->isFatal()) {
                $this->stateTracker->error("received_fatal_alert_{$description->name}");
            }
        }
    }

    // === Proper Signature Creation ===

    private function createCertificateVerifySignature(): string
    {
        $transcript = $this->context->getHandshakeTranscript();
        $signatureContext = $this->buildSignatureContext($transcript);

        $privateKey = $this->context->getPrivateKey();
        $signatureScheme = $this->context->getNegotiatedSignatureScheme();

        if (!$privateKey || !$signatureScheme) {
            throw new CraftException("Missing private key or signature scheme for CertificateVerify");
        }

        return CertificateUtils::createSignature($signatureContext, $privateKey, $signatureScheme);
    }

    private function buildSignatureContext(string $transcript): string
    {
        $contextString = $this->stateTracker->isClient() ?
            "TLS 1.3, client CertificateVerify" :
            "TLS 1.3, server CertificateVerify";

        return str_repeat("\x20", 64) .
            $contextString .
            "\x00" .
            hash('sha256', $transcript, true);
    }
}
