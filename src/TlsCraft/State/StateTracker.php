<?php

namespace Php\TlsCraft\State;

/**
 * Pure state machine - tracks states and validates transitions
 */
class StateTracker
{
    private ConnectionState $connectionState = ConnectionState::INITIAL;
    private HandshakeState $handshakeState = HandshakeState::START;
    private array $stateChangeCallbacks = [];
    private bool $isClient;

    public function __construct(bool $isClient = true)
    {
        $this->isClient = $isClient;

        if (!$isClient) {
            $this->handshakeState = HandshakeState::WAIT_CLIENT_HELLO;
        }
    }

    public function isClient(): bool
    {
        return $this->isClient;
    }

    public function getConnectionState(): ConnectionState
    {
        return $this->connectionState;
    }

    public function getHandshakeState(): HandshakeState
    {
        return $this->handshakeState;
    }

    public function isHandshakeComplete(): bool
    {
        return $this->handshakeState === HandshakeState::CONNECTED;
    }

    public function isConnected(): bool
    {
        return $this->connectionState === ConnectionState::CONNECTED;
    }

    public function isClosed(): bool
    {
        return $this->connectionState === ConnectionState::CLOSED;
    }

    public function canTransitionConnection(ConnectionState $newState): bool
    {
        return $this->connectionState->canTransitionTo($newState);
    }

    public function transitionConnection(ConnectionState $newState, ?string $reason = null): bool
    {
        if (!$this->canTransitionConnection($newState)) {
            return false;
        }

        $oldState = $this->connectionState;
        $this->connectionState = $newState;

        $this->notifyStateChange($oldState, $newState, $reason);
        return true;
    }

    public function transitionHandshake(HandshakeState $newState): void
    {
        $oldState = $this->handshakeState;
        $this->handshakeState = $newState;

        // Auto-transition connection state when handshake completes
        if ($newState === HandshakeState::CONNECTED &&
            $this->connectionState === ConnectionState::HANDSHAKING) {
            $this->transitionConnection(ConnectionState::CONNECTED, 'handshake_complete');
        }

        $this->notifyHandshakeStateChange($oldState, $newState);
    }

    public function startHandshake(): bool
    {
        return $this->transitionConnection(ConnectionState::HANDSHAKING, 'handshake_started');
    }

    public function completeHandshake(): void
    {
        $this->transitionHandshake(HandshakeState::CONNECTED);
    }

    public function close(bool $abrupt = false): bool
    {
        if ($abrupt) {
            return $this->transitionConnection(ConnectionState::CLOSED, 'abrupt_close');
        }

        if ($this->connectionState === ConnectionState::CONNECTED) {
            if ($this->transitionConnection(ConnectionState::CLOSING, 'graceful_close')) {
                return $this->transitionConnection(ConnectionState::CLOSED, 'close_complete');
            }
        }

        return $this->transitionConnection(ConnectionState::CLOSED, 'force_close');
    }

    public function error(string $reason): bool
    {
        return $this->transitionConnection(ConnectionState::ERROR, $reason);
    }

    public function onStateChange(callable $callback): void
    {
        $this->stateChangeCallbacks[] = $callback;
    }

    private function notifyStateChange(ConnectionState $oldState, ConnectionState $newState, ?string $reason): void
    {
        foreach ($this->stateChangeCallbacks as $callback) {
            $callback($oldState, $newState, $reason);
        }
    }

    private function notifyHandshakeStateChange(HandshakeState $oldState, HandshakeState $newState): void
    {
        foreach ($this->stateChangeCallbacks as $callback) {
            if (is_callable([$callback, '__invoke'])) {
                $reflection = new \ReflectionFunction($callback);
                if ($reflection->getNumberOfParameters() > 3) {
                    $callback(null, null, null, $oldState, $newState);
                }
            }
        }
    }
}
