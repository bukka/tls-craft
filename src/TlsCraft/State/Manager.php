<?php

declare(strict_types=1);

namespace Php\TlsCraft\State;

use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Handshake\Certificate;
use Php\TlsCraft\Handshake\ClientHello;
use Php\TlsCraft\Handshake\Context;
use Php\TlsCraft\Handshake\Finished;
use Php\TlsCraft\Handshake\HandshakeMessage;
use Php\TlsCraft\Handshake\KeyUpdate;
use Php\TlsCraft\Handshake\ServerHello;
use Php\TlsCraft\Protocol\HandshakeType;
use ReflectionFunction;

/**
 * Application traffic and key state
 */
class Manager: string
{
    private ConnectionState $connectionState = ConnectionState::INITIAL;
    private HandshakeState $handshakeState = HandshakeState::START;
    private TrafficState $trafficState;
    private array $stateChangeCallbacks = [];
    private bool $isClient;
    private ?Context $handshakeContext = null;

    public function __construct(bool $isClient = true)
    {
        $this->isClient = $isClient;
        $this->trafficState = new TrafficState();
        $this->handshakeContext = new Context($isClient);

        if (!$isClient) {
            $this->handshakeState = HandshakeState::WAIT_CLIENT_HELLO;
        }
    }

    public function getCurrentState(): ConnectionState
    {
        return $this->connectionState;
    }

    public function getHandshakeState(): HandshakeState
    {
        return $this->handshakeState;
    }

    public function getTrafficState(): TrafficState
    {
        return $this->trafficState;
    }

    public function getHandshakeContext(): Context
    {
        return $this->handshakeContext;
    }

    public function isClient(): bool
    {
        return $this->isClient;
    }

    public function isHandshakeComplete(): bool
    {
        return $this->handshakeState === HandshakeState::CONNECTED;
    }

    public function isClosed(): bool
    {
        return $this->connectionState === ConnectionState::CLOSED;
    }

    public function startHandshake(): bool
    {
        return $this->transition(ConnectionState::HANDSHAKING, 'handshake_started');
    }

    public function transition(ConnectionState $newState, ?string $reason = null): bool
    {
        if (!$this->canTransition($newState)) {
            return false;
        }

        $oldState = $this->connectionState;
        $this->connectionState = $newState;

        $this->notifyStateChange($oldState, $newState, $reason);
        return true;
    }

    public function canTransition(ConnectionState $newState): bool
    {
        return $this->connectionState->canTransitionTo($newState);
    }

    private function notifyStateChange(ConnectionState $oldState, ConnectionState $newState, ?string $reason): void
    {
        foreach ($this->stateChangeCallbacks as $callback) {
            $callback($oldState, $newState, $reason);
        }
    }

    public function processHandshakeMessage(HandshakeMessage $message): void
    {
        // Add to transcript
        $this->handshakeContext->addHandshakeMessage($message);

        // Process based on the current state and message type
        $this->validateHandshakeMessage($message);

        // Update state based on the message
        $this->updateHandshakeState($message);
    }

    private function validateHandshakeMessage(HandshakeMessage $message): void
    {
        $expectedTypes = $this->getExpectedMessageTypes();

        if (!in_array($message->type, $expectedTypes)) {
            throw new ProtocolViolationException(
                "Unexpected handshake message {$message->type->name} in state {$this->handshakeState->value}"
            );
        }
    }

    private function getExpectedMessageTypes(): array
    {
        return match ($this->handshakeState) {
            HandshakeState::START => $this->isClient ? [HandshakeType::SERVER_HELLO] : [HandshakeType::CLIENT_HELLO],
            HandshakeState::WAIT_CLIENT_HELLO => [HandshakeType::CLIENT_HELLO],
            HandshakeState::WAIT_SERVER_HELLO => [HandshakeType::SERVER_HELLO],
            HandshakeState::WAIT_ENCRYPTED_EXTENSIONS => [HandshakeType::ENCRYPTED_EXTENSIONS],
            HandshakeState::WAIT_CERTIFICATE => [HandshakeType::CERTIFICATE],
            HandshakeState::WAIT_CERTIFICATE_VERIFY => [HandshakeType::CERTIFICATE_VERIFY],
            HandshakeState::WAIT_FINISHED => [HandshakeType::FINISHED],
            HandshakeState::WAIT_FLIGHT2 => [
                HandshakeType::CERTIFICATE,
                HandshakeType::CERTIFICATE_VERIFY,
                HandshakeType::FINISHED
            ],
            HandshakeState::CONNECTED => [HandshakeType::KEY_UPDATE],
        };
    }

    private function updateHandshakeState(HandshakeMessage $message): void
    {
        match ($message->type) {
            HandshakeType::CLIENT_HELLO => $this->handleClientHello($message),
            HandshakeType::SERVER_HELLO => $this->handleServerHello($message),
            HandshakeType::ENCRYPTED_EXTENSIONS => $this->handleEncryptedExtensions(),
            HandshakeType::CERTIFICATE => $this->handleCertificate($message),
            HandshakeType::CERTIFICATE_VERIFY => $this->handleCertificateVerify(),
            HandshakeType::FINISHED => $this->handleFinished($message),
            HandshakeType::KEY_UPDATE => $this->handleKeyUpdate($message),
            default => throw new ProtocolViolationException("Unsupported handshake message")
        };
    }

    private function handleClientHello(ClientHello $clientHello): void
    {
        $this->handshakeContext->processClientHello($clientHello);

        if ($this->isClient) {
            throw new ProtocolViolationException("Client received ClientHello");
        }

        $this->transitionHandshake(HandshakeState::WAIT_FLIGHT2);
    }

    private function handleServerHello(ServerHello $serverHello): void
    {
        $this->handshakeContext->processServerHello($serverHello);

        if (!$this->isClient) {
            throw new ProtocolViolationException("Server received ServerHello");
        }

        // Derive handshake secrets after ServerHello
        $this->handshakeContext->deriveHandshakeSecrets();

        $this->transitionHandshake(HandshakeState::WAIT_ENCRYPTED_EXTENSIONS);
    }

    private function handleEncryptedExtensions(): void
    {
        $this->transitionHandshake(HandshakeState::WAIT_CERTIFICATE);
    }

    private function handleCertificate(Certificate $certificate): void
    {
        $this->handshakeContext->setCertificateChain($certificate->certificateList);
        $this->transitionHandshake(HandshakeState::WAIT_CERTIFICATE_VERIFY);
    }

    private function handleCertificateVerify(): void
    {
        $this->transitionHandshake(HandshakeState::WAIT_FINISHED);
    }

    private function handleFinished(Finished $finished): void
    {
        // Verify the finished data
        $expectedFinished = $this->handshakeContext->getFinishedData(!$this->isClient);

        if (!hash_equals($expectedFinished, $finished->verifyData)) {
            throw new ProtocolViolationException("Invalid Finished message");
        }

        $this->completeHandshake();
    }

    public function completeHandshake(): void
    {
        // Validate handshake completion
        $this->handshakeContext->validateNegotiation();

        // Derive application traffic secrets
        $this->handshakeContext->deriveApplicationSecrets();

        // Update traffic state with application keys
        $keys = $this->handshakeContext->getApplicationKeys($this->isClient);
        $peerKeys = $this->handshakeContext->getApplicationKeys(!$this->isClient);

        $this->trafficState->updateKeys(
            $peerKeys['key'], // read key (from peer)
            $keys['key'],     // write key (our key)
            $peerKeys['iv'],  // read IV
            $keys['iv']       // write IV
        );

        $this->transitionHandshake(HandshakeState::CONNECTED);
    }

    public function transitionHandshake(HandshakeState $newState): void
    {
        $oldState = $this->handshakeState;
        $this->handshakeState = $newState;

        // Auto-transition connection state when handshake completes
        if ($newState === HandshakeState::CONNECTED && $this->connectionState === ConnectionState::HANDSHAKING) {
            $this->transition(ConnectionState::CONNECTED, 'handshake_complete');
        }

        $this->notifyHandshakeStateChange($oldState, $newState);
    }

    private function notifyHandshakeStateChange(HandshakeState $oldState, HandshakeState $newState): void
    {
        foreach ($this->stateChangeCallbacks as $callback) {
            if (method_exists($callback, '__invoke') &&
                (new ReflectionFunction($callback))->getNumberOfParameters() > 3) {
                $callback(null, null, null, $oldState, $newState);
            }
        }
    }

    private function handleKeyUpdate(KeyUpdate $keyUpdate): void
    {
        if (!$this->isConnected()) {
            throw new ProtocolViolationException("KeyUpdate received before connection established");
        }

        // Update traffic keys
        $this->trafficState->scheduleKeyUpdate();

        // If peer requested update, we need to send one too
        if ($keyUpdate->requestUpdate) {
            // This would be handled by the connection layer
        }
    }

    public function isConnected(): bool
    {
        return $this->connectionState === ConnectionState::CONNECTED;
    }

    public function close(bool $abrupt = false): bool
    {
        if ($abrupt) {
            return $this->transition(ConnectionState::CLOSED, 'abrupt_close');
        }

        if ($this->connectionState === ConnectionState::CONNECTED) {
            if ($this->transition(ConnectionState::CLOSING, 'graceful_close')) {
                return $this->transition(ConnectionState::CLOSED, 'close_complete');
            }
        }

        return $this->transition(ConnectionState::CLOSED, 'force_close');
    }

    public function error(string $reason): bool
    {
        return $this->transition(ConnectionState::ERROR, $reason);
    }

    public function onStateChange(callable $callback): void
    {
        $this->stateChangeCallbacks[] = $callback;
    }
}
