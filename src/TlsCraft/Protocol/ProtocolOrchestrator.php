<?php

namespace Php\TlsCraft\Protocol;

use Php\TlsCraft\Connection\Connection;
use Php\TlsCraft\Context;
use Php\TlsCraft\Control\FlowController;
use Php\TlsCraft\Crypto\CertificateChain;
use Php\TlsCraft\Crypto\CertificateSigner;
use Php\TlsCraft\Crypto\CryptoFactory;
use Php\TlsCraft\Crypto\SignatureScheme;
use Php\TlsCraft\Exceptions\{AlertException, CraftException, ProtocolViolationException};
use Php\TlsCraft\Handshake\MessageFactory;
use Php\TlsCraft\Handshake\Messages\{KeyUpdateMessage, Message};
use Php\TlsCraft\Handshake\MessageSerializer;
use Php\TlsCraft\Handshake\ProcessorManager;
use Php\TlsCraft\Logger;
use Php\TlsCraft\Record\{EncryptedLayer, LayerFactory, Record, RecordFactory};
use Php\TlsCraft\State\{HandshakeState, ProtocolValidator, StateTracker};

/**
 * ProtocolOrchestrator - Manages TLS 1.3 handshake and connection lifecycle
 */
class ProtocolOrchestrator
{
    private EncryptedLayer $recordLayer;
    private CertificateSigner $certificateSigner;
    private string $handshakeBuffer = '';

    public function __construct(
        private readonly StateTracker $stateTracker,
        private readonly ProtocolValidator $validator,
        private readonly Context $context,
        private readonly ProcessorManager $processorManager,
        private readonly CryptoFactory $cryptoFactory,
        private readonly LayerFactory $layerFactory,
        private readonly RecordFactory $recordFactory,
        private readonly MessageFactory $messageFactory,
        private readonly MessageSerializer $messageSerializer,
        private readonly Connection $connection,
        private readonly ?FlowController $flowController,
    ) {
        $this->recordLayer = $this->layerFactory->createEncryptedLayer($connection, $context, $this->flowController);
        $this->certificateSigner = $this->cryptoFactory->createCertificateSigner();
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

        // Load client certificate from config if configured
        // (will be sent if server requests it via CertificateRequest)
        if ($this->context->getConfig()->hasCertificate()) {
            $this->context->loadCertificateFromConfig();
        }

        // Send ClientHello
        $clientHello = $this->messageFactory->createClientHello();
        $this->sendHandshakeMessage($clientHello, false);

        // Process server handshake messages
        $this->processServerHandshakeMessages();

        // After receiving server's Finished, send client certificate if requested
        if ($this->context->getCertificateRequestContext() !== null) {
            $this->sendClientCertificateFlight();
        }

        // Send client Finished
        $finished = $this->messageFactory->createFinished(true);
        $this->sendHandshakeMessage($finished);

        // Update state to indicate handshake is complete
        $this->context->setHandshakeComplete(true);

        // Derive application traffic secrets
        $this->context->deriveApplicationSecrets();
    }

    public function performServerHandshake(): void
    {
        $this->stateTracker->startHandshake();

        // Wait for ClientHello
        $this->waitForClientHello();

        // Only load certificate if we're not doing PSK-only resumption
        if (!$this->context->isResuming() || $this->context->supportsPskDhe()) {
            if (!$this->context->getConfig()->hasCertificate()) {
                throw new CraftException('Server certificate not configured');
            }
            $this->context->loadCertificateFromConfig();
        } else {
            Logger::debug('PSK-only resumption: certificate not required');
        }

        // Send server handshake flight
        $this->sendServerHandshakeFlight();

        // Wait for client Finished (and optionally client certificate)
        $this->waitForClientFinished();

        // Update state to indicate handshake is complete
        $this->context->setHandshakeComplete(true);

        // Derive application traffic secrets
        $this->context->deriveApplicationSecrets();

        // Send a session ticket if resumption is enabled
        $this->sendNewSessionTicketIfEnabled();
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
            }

            // Ignore other types (e.g., ChangeCipherSpec)
        }
    }

    // === Post-Handshake Operations ===

    private function sendNewSessionTicketIfEnabled(): void
    {
        if (!$this->stateTracker->isClient()
            && $this->context->getConfig()->isSessionResumptionEnabled()) {

            $ticket = $this->messageFactory->createNewSessionTicket();
            $this->sendHandshakeMessage($ticket);

            Logger::debug('Sent NewSessionTicket to client');
        }
    }

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

        Logger::debug('sendHandshakeMessage: After adding to transcript', [
            'message_type' => $message->type->name,
            'transcript_count_after' => $this->context->getHandshakeTranscript()->count(),
            'transcript_types_after' => $this->context->getHandshakeTranscript()->getAllTypes(),
        ]);

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

        // For PSK resumption without (EC)DHE, skip certificate authentication
        if ($this->context->isResuming()) {
            Logger::debug('PSK resumption: skipping Certificate and CertificateVerify');

            // 3. Finished (for PSK resumption)
            $finished = $this->messageFactory->createFinished(false);
            $this->sendHandshakeMessage($finished);
            return;
        }

        // Full handshake continues with certificate authentication

        // 3. CertificateRequest (optional)
        if ($this->context->getConfig()->isRequestClientCertificate()) {
            $certificateRequest = $this->messageFactory->createCertificateRequest();
            $this->sendHandshakeMessage($certificateRequest);
            Logger::debug('Sent CertificateRequest to client');
        }

        // 4. Certificate (server's certificate)
        $certificateChain = $this->context->getServerCertificateChain();
        $certificate = $this->messageFactory->createCertificate($certificateChain);
        $this->sendHandshakeMessage($certificate);

        // 5. CertificateVerify (server's signature)
        $signature = $this->createServerCertificateVerifySignature();
        $certificateVerify = $this->messageFactory->createCertificateVerify($signature);
        $this->sendHandshakeMessage($certificateVerify);

        // 6. Finished
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
            } elseif ($record->isAlert()) {
                $this->handleAlertRecord($record);
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
        $length = unpack('N', "\x00".substr($buffer, 1, 3))[1];

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
            $this->stateTracker->isClient(),
            $this->context->isResuming(),
        )) {
            $handshakeState = $this->stateTracker->getHandshakeState()->value;
            throw new ProtocolViolationException("Unexpected handshake message {$type->name} in state {$handshakeState}");
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
                // After EncryptedExtensions, we might get CertificateRequest or Certificate
                // Stay in current state, will transition based on next message
                $this->stateTracker->transitionHandshake(HandshakeState::WAIT_CERTIFICATE);
                break;

            case HandshakeType::CERTIFICATE_REQUEST:
                $certificateRequest = $this->messageFactory->createCertificateRequestFromWire($data);
                $this->processorManager->processCertificateRequest($certificateRequest);
                // State remains WAIT_CERTIFICATE - server still needs to send its certificate
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
                $this->handleKeyUpdate($keyUpdate);
                break;

            case HandshakeType::NEW_SESSION_TICKET:
                $newSessionTicket = $this->messageFactory->createNewSessionTicketFromWire($data);
                $this->processorManager->processNewSessionTicket($newSessionTicket);
                break;

            default:
                throw new ProtocolViolationException("Unsupported handshake message: {$type->name}");
        }
    }

    /**
     * Send client certificate flight (after receiving server's Finished)
     * This is called when the server sent a CertificateRequest
     */
    private function sendClientCertificateFlight(): void
    {
        // Check if we have a private key configured
        if ($this->context->getClientPrivateKey()) {
            // Send Certificate with the context from CertificateRequest
            $certificateChain = $this->context->getClientCertificateChain();
            $certificate = $this->messageFactory->createCertificate($certificateChain);
            $this->sendHandshakeMessage($certificate);

            // Send CertificateVerify
            $signature = $this->createClientCertificateVerifySignature();
            $certificateVerify = $this->messageFactory->createCertificateVerify($signature);
            $this->sendHandshakeMessage($certificateVerify);

            Logger::debug('Sent client certificate and signature');
        } else {
            // Send empty Certificate message (no client cert available)
            $certificate = $this->messageFactory->createCertificate(
                CertificateChain::fromCertificates([]),
            );
            $this->sendHandshakeMessage($certificate);

            Logger::debug('Sent empty client certificate (no cert configured)');
        }
    }

    private function handleKeyUpdate(KeyUpdateMessage $keyUpdate): void
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

    private function handleAlertRecord(Record $record): void
    {
        if (strlen($record->payload) >= 2) {
            $level = AlertLevel::fromByte($record->payload[0]);
            $description = AlertDescription::fromByte($record->payload[1]);

            if ($description === AlertDescription::CLOSE_NOTIFY) {
                Logger::error('Received close notify');
                $this->stateTracker->close(false);
            } elseif ($description->isFatal()) {
                Logger::error('Received fatal alert', [
                    'name' => $description->name,
                    'level' => $level->name,
                ]);
                $this->stateTracker->error("received_fatal_alert_{$description->name}");
                throw new AlertException("Received fatal alert: {$description->name}");
            }
        }
    }

    // === Signature Creation ===

    /**
     * Create signature for server's CertificateVerify
     */
    private function createServerCertificateVerifySignature(): string
    {
        $transcript = $this->context->getHandshakeTranscript();

        $signatureContext = $this->buildSignatureContext(
            $transcript->getThrough(HandshakeType::CERTIFICATE),
            false, // server
        );

        $privateKey = $this->context->getServerPrivateKey();
        $signatureScheme = $this->context->getNegotiatedSignatureScheme();

        if (!$privateKey || !$signatureScheme) {
            throw new CraftException('Missing private key or signature scheme for server CertificateVerify');
        }

        return $this->certificateSigner->createSignature($signatureContext, $privateKey, $signatureScheme);
    }

    /**
     * Create signature for client's CertificateVerify
     */
    private function createClientCertificateVerifySignature(): string
    {
        $transcript = $this->context->getHandshakeTranscript();
        $transcriptData = $transcript->getAll();

        $signatureContext = $this->buildSignatureContext(
            $transcriptData,
            true, // client
        );

        Logger::debug('Built signature context', [
            'context_length' => strlen($signatureContext),
            'context' => bin2hex($signatureContext),
        ]);

        $privateKey = $this->context->getClientPrivateKey();

        // Choose signature scheme that matches both:
        // 1. Client certificate's key type
        // 2. Server's requested signature algorithms
        $signatureScheme = $this->selectClientSignatureScheme();

        if (!$privateKey || !$signatureScheme) {
            throw new CraftException('Missing client private key or signature scheme for CertificateVerify');
        }

        Logger::debug('Using signature scheme for client CertificateVerify', [
            'scheme' => $signatureScheme->name,
        ]);

        return $this->certificateSigner->createSignature($signatureContext, $privateKey, $signatureScheme, $this->context->getClientCertificateChain()->getLeafCertificate());
    }

    /**
     * Build signature context for CertificateVerify
     */
    private function buildSignatureContext(string $transcript, bool $isClient): string
    {
        $contextString = $isClient ?
            'TLS 1.3, client CertificateVerify' :
            'TLS 1.3, server CertificateVerify';

        $hashAlgo = $this->context->getNegotiatedCipherSuite()->getHashAlgorithm();

        $transcriptHash = hash($hashAlgo, $transcript, true);

        $context = str_repeat("\x20", 64).
            $contextString.
            "\x00".
            $transcriptHash;

        Logger::debug('Building signature context', [
            'is_client' => $isClient,
            'hash_algo' => $hashAlgo,
            'transcript_length' => strlen($transcript),
            'transcript_hash' => bin2hex($transcriptHash),
            'context' => bin2hex($context),
        ]);

        return $context;
    }

    /**
     * Select appropriate signature scheme for client certificate
     */
    private function selectClientSignatureScheme(): ?SignatureScheme
    {
        $clientCert = $this->context->getClientCertificateChain();
        if (!$clientCert) {
            return null;
        }

        // Get schemes supported by the client certificate
        $certSupportedSchemes = $clientCert->getSupportedSignatureSchemes();

        // Get schemes requested by server
        $serverRequestedSchemes = $this->context->getServerSignatureAlgorithms();

        // If server didn't request specific algorithms, use first cert-supported scheme
        if (empty($serverRequestedSchemes)) {
            return $certSupportedSchemes[0] ?? null;
        }

        // Find first matching scheme
        foreach ($certSupportedSchemes as $certScheme) {
            foreach ($serverRequestedSchemes as $serverScheme) {
                if ($certScheme === $serverScheme) {
                    return $certScheme;
                }
            }
        }

        return null; // No compatible scheme found
    }
}
