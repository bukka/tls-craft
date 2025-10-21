<?php

namespace Php\TlsCraft\Protocol;

use Php\TlsCraft\Connection\Connection;
use Php\TlsCraft\Context;
use Php\TlsCraft\Control\{FlowController};
use Php\TlsCraft\Crypto\CertificateUtils;
use Php\TlsCraft\Exceptions\{CraftException, ProtocolViolationException};
use Php\TlsCraft\Handshake\MessageFactory;
use Php\TlsCraft\Handshake\Messages\{KeyUpdate, Message};
use Php\TlsCraft\Handshake\MessageSerializer;
use Php\TlsCraft\Handshake\ProcessorManager;
use Php\TlsCraft\Record\{EncryptedLayer, LayerFactory, Record, RecordFactory};
use Php\TlsCraft\State\{HandshakeState, ProtocolValidator, StateTracker};

/**
 * Updated ProtocolOrchestrator with clean typing and proper integration
 */
class ProtocolOrchestrator
{
    private EncryptedLayer $recordLayer;
    private string $handshakeBuffer = '';

    public function __construct(
        private readonly StateTracker $stateTracker,
        private readonly ProtocolValidator $validator,
        private readonly Context $context,
        private readonly ProcessorManager $processorManager,
        private readonly LayerFactory $layerFactory,
        private readonly RecordFactory $recordFactory,
        private readonly MessageFactory $messageFactory,
        private readonly MessageSerializer $messageSerializer,
        private readonly Connection $connection,
        private readonly ?FlowController $flowController,
    ) {
        $this->recordLayer = $this->layerFactory->createEncryptedLayer($connection, $context, $this->flowController);
    }

    public function isConnected(): bool
    {
        return $this->stateTracker->isConnected() && $this->connection->isConnected();
    }

    public function getStateTracker(): StateTracker
    {
        return $this->stateTracker;
    }

    public function getContext(): Context
    {
        return $this->context;
    }

    // === Handshake Operations ===

    public function performClientHandshake(): void
    {
        $this->stateTracker->startHandshake();

        // Send ClientHello
        $clientHello = $this->messageFactory->createClientHello();
        $this->sendHandshakeMessage($clientHello, false);

        // Process server handshake messages
        $this->processServerHandshakeMessages();

        // Send client Finished
        $finished = $this->messageFactory->createFinished(true);
        $this->sendHandshakeMessage($finished);

        // Derive application traffic secrets
        $this->context->deriveApplicationSecrets();
    }

    public function performServerHandshake(): void
    {
        $this->stateTracker->startHandshake();

        // Wait for ClientHello
        $this->waitForClientHello();

        // Send server handshake flight
        $this->sendServerHandshakeFlight();

        // Wait for client Finished
        $this->waitForClientFinished();

        // Derive application traffic secrets
        $this->context->deriveApplicationSecrets();
    }

    // === Application Data Operations ===

    public function sendApplicationData(string $data): void
    {
        if (!$this->stateTracker->isConnected()) {
            throw new CraftException('Cannot send application data: not connected');
        }

        $record = $this->recordFactory->createApplicationData($data);
        $this->recordLayer->sendRecord($record);
    }

    public function receiveApplicationData(): ?string
    {
        if (!$this->stateTracker->isConnected()) {
            throw new CraftException('Cannot receive application data: not connected');
        }

        // Keep reading until we get application data
        while (true) {
            $record = $this->recordLayer->receiveRecord();
            if (!$record) {
                return null; // Connection closed or no data available
            }

            if ($record->isApplicationData()) {
                return $record->payload;
            }

            // Handle post-handshake messages (NewSessionTicket, KeyUpdate, etc.)
            if ($record->isHandshake()) {
                $this->processHandshakeRecord($record);
                continue; // Keep looking for application data
            }

            if ($record->isAlert()) {
                $this->handleAlertRecord($record);
                return null;
            }

            // Ignore other types (e.g., ChangeCipherSpec)
        }
    }

    // === Post-Handshake Operations ===

    public function sendKeyUpdate(bool $requestUpdate = false): void
    {
        if (!$this->stateTracker->isConnected()) {
            throw new CraftException('Cannot send KeyUpdate: not connected');
        }

        $keyUpdate = $this->messageFactory->createKeyUpdate($requestUpdate);
        $this->sendHandshakeMessage($keyUpdate);

        // Update our own keys
        $this->context->updateTrafficKeys();
    }

    public function sendAlert(AlertLevel $level, AlertDescription $description): void
    {
        $alertData = $this->messageFactory->createAlert($level, $description);
        $record = $this->recordFactory->createAlert($alertData);
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
        // Serialize message
        $serializedMessage = $this->messageSerializer->serialize($message);

        // Add to context transcript
        $this->context->addHandshakeMessage($serializedMessage);

        // Send record
        $record = $this->recordFactory->createHandshake($serializedMessage, $encrypted);
        $this->recordLayer->sendRecord($record);
    }

    private function waitForClientHello(): void
    {
        while ($this->stateTracker->getHandshakeState() === HandshakeState::WAIT_CLIENT_HELLO) {
            $record = $this->recordLayer->receiveRecord();
            if (!$record) {
                throw new CraftException('Connection closed waiting for ClientHello');
            }

            if ($record->isHandshake()) {
                $this->processHandshakeRecord($record);
            }
        }
    }

    private function sendServerHandshakeFlight(): void
    {
        // 1. ServerHello
        $serverHello = $this->messageFactory->createServerHello();
        $this->sendHandshakeMessage($serverHello, false);

        // 2. EncryptedExtensions
        $encryptedExtensions = $this->messageFactory->createEncryptedExtensions();
        $this->sendHandshakeMessage($encryptedExtensions);

        // 3. Certificate
        $certificateChain = $this->context->getCertificateChain();
        $certificate = $this->messageFactory->createCertificate($certificateChain);
        $this->sendHandshakeMessage($certificate);

        // 4. CertificateVerify
        $signature = $this->createCertificateVerifySignature();
        $certificateVerify = $this->messageFactory->createCertificateVerify($signature);
        $this->sendHandshakeMessage($certificateVerify);

        // 5. Finished
        $finished = $this->messageFactory->createFinished(false);
        $this->sendHandshakeMessage($finished);
    }

    private function waitForClientFinished(): void
    {
        while (!$this->stateTracker->isHandshakeComplete()) {
            $record = $this->recordLayer->receiveRecord();
            if (!$record) {
                throw new CraftException('Connection closed waiting for client Finished');
            }

            if ($record->isHandshake()) {
                $this->processHandshakeRecord($record);
            }
        }
    }

    // === Enhanced Message Processing with Processors ===

    private function processServerHandshakeMessages(): void
    {
        // Process messages until handshake is complete
        while (!$this->stateTracker->isHandshakeComplete()) {
            // Try to process any buffered messages first
            $processedAny = false;
            while ($this->handshakeBuffer !== '') {
                $message = $this->parseNextHandshakeMessage($this->handshakeBuffer);
                if ($message === null) {
                    break; // Need more data
                }

                $this->processHandshakeMessage($message['type'], $message['data']);
                $processedAny = true;
            }

            // If we processed messages from buffer, continue the loop
            if ($processedAny) {
                continue;
            }

            // Need more data - receive another record
            $record = $this->recordLayer->receiveRecord();
            if (!$record) {
                throw new CraftException('Connection closed during handshake');
            }

            // Handle ChangeCipherSpec
            if ($record->contentType === ContentType::CHANGE_CIPHER_SPEC) {
                continue; // Ignore for TLS 1.3
            }

            if ($record->isHandshake()) {
                $this->processHandshakeRecord($record);
            } elseif ($record->isAlert()) {
                $this->handleAlertRecord($record);
            }
        }
    }

    private function processHandshakeRecord(Record $record): void
    {
        if (!$record->isHandshake()) {
            throw new CraftException('Expected handshake record');
        }

        // Add to buffer
        $this->handshakeBuffer .= $record->payload;

        // Try to parse and process all complete messages in the buffer
        while ($this->handshakeBuffer !== '') {
            $message = $this->parseNextHandshakeMessage($this->handshakeBuffer);
            if ($message === null) {
                break; // No complete message available
            }

            $this->processHandshakeMessage($message['type'], $message['data']);
        }
    }

    private function parseNextHandshakeMessage(string &$buffer): ?array
    {
        if (strlen($buffer) < 4) {
            return null; // Need at least 4 bytes for header
        }

        // Parse handshake message header
        $type = HandshakeType::fromByte($buffer[0]);
        $length = unpack('N', "\x00" . substr($buffer, 1, 3))[1];

        if (strlen($buffer) < 4 + $length) {
            return null; // Complete message not yet available
        }

        // Extract complete message (including header)
        $messageData = substr($buffer, 0, 4 + $length);
        $buffer = substr($buffer, 4 + $length); // Remove from buffer

        return ['type' => $type, 'data' => $messageData];
    }

    private function processHandshakeMessage(HandshakeType $type, string $data): void
    {
        // Validate message type for the current state
        if (!$this->validator->validateHandshakeMessage(
            $type,
            $this->stateTracker->getHandshakeState(),
            $this->stateTracker->isClient()
        )) {
            $handshakeState = $this->stateTracker->getHandshakeState()->value;
            throw new ProtocolViolationException(
                "Unexpected handshake message {$type->name} in state {$handshakeState}"
            );
        }

        // Add to context transcript
        $this->context->addHandshakeMessage($data);

        // Parse to specific type and handle with processors
        switch ($type) {
            case HandshakeType::CLIENT_HELLO:
                $clientHello = $this->messageFactory->createClientHelloFromWire($data);
                $this->processorManager->processClientHello($clientHello);
                $this->stateTracker->transitionHandshake(HandshakeState::WAIT_FLIGHT2);
                break;

            case HandshakeType::SERVER_HELLO:
                $serverHello = $this->messageFactory->createServerHelloFromWire($data);
                $this->processorManager->processServerHello($serverHello);
                $this->stateTracker->transitionHandshake(HandshakeState::WAIT_ENCRYPTED_EXTENSIONS);
                break;

            case HandshakeType::ENCRYPTED_EXTENSIONS:
                $encryptedExtensions = $this->messageFactory->createEncryptedExtensionsFromWire($data);
                $this->processorManager->processEncryptedExtensions($encryptedExtensions);
                $this->stateTracker->transitionHandshake(HandshakeState::WAIT_CERTIFICATE);
                break;

            case HandshakeType::CERTIFICATE:
                $certificate = $this->messageFactory->createCertificateFromWire($data);
                $this->processorManager->processCertificate($certificate);
                $this->stateTracker->transitionHandshake(HandshakeState::WAIT_CERTIFICATE_VERIFY);
                break;

            case HandshakeType::CERTIFICATE_VERIFY:
                $certificateVerify = $this->messageFactory->createCertificateVerifyFromWire($data);
                $this->processorManager->processCertificateVerify($certificateVerify);
                $this->stateTracker->transitionHandshake(HandshakeState::WAIT_FINISHED);
                break;

            case HandshakeType::FINISHED:
                $finished = $this->messageFactory->createFinishedFromWire($data);
                $this->processorManager->processFinished($finished);
                $this->stateTracker->completeHandshake();
                break;

            case HandshakeType::KEY_UPDATE:
                $keyUpdate = $this->messageFactory->createKeyUpdateFromWire($data);
                $this->processorManager->processKeyUpdate($keyUpdate);
                break;

            case HandshakeType::NEW_SESSION_TICKET:
                // For now, just acknowledge and ignore
                // In the future; it can store the ticket for session resumption.
                break;

            default:
                throw new ProtocolViolationException("Unsupported handshake message: {$type->name}");
        }
    }

    private function handleKeyUpdate(KeyUpdate $keyUpdate): void
    {
        if (!$this->stateTracker->isConnected()) {
            throw new ProtocolViolationException('KeyUpdate received before connection established');
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
            throw new CraftException('Missing private key or signature scheme for CertificateVerify');
        }

        return CertificateUtils::createSignature($signatureContext, $privateKey, $signatureScheme);
    }

    private function buildSignatureContext(string $transcript): string
    {
        $contextString = $this->stateTracker->isClient() ?
            'TLS 1.3, client CertificateVerify' :
            'TLS 1.3, server CertificateVerify';

        return str_repeat("\x20", 64).
            $contextString.
            "\x00".
            hash('sha256', $transcript, true);
    }
}
