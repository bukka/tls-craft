<?php

namespace Php\TlsCraft\Connection;

use Php\TlsCraft\Control\FlowController;
use Php\TlsCraft\Control\MessageCrafter;
use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Exceptions\StateException;
use Php\TlsCraft\Handshake\HandshakeMessage;
use Php\TlsCraft\Protocol\AlertDescription;
use Php\TlsCraft\Protocol\AlertLevel;
use Php\TlsCraft\Protocol\ContentType;
use Php\TlsCraft\Protocol\HandshakeType;
use Php\TlsCraft\Record\Builder;
use Php\TlsCraft\Record\Layer;
use Php\TlsCraft\Record\Record;
use Php\TlsCraft\State\ConnectionState;
use Php\TlsCraft\State\HandshakeState;
use Php\TlsCraft\State\Manager;

class ControlledConnection
{
    private Socket $socket;
    private Manager $stateManager;
    public Layer $recordLayer;
    private ?FlowController $controller;

    public function __construct(
        Socket $socket,
        Manager $stateManager,
        ?FlowController $controller = null
    ) {
        $this->socket = $socket;
        $this->stateManager = $stateManager;
        $this->controller = $controller;

        $this->recordLayer = new Layer(
            $socket->getResource(),
            $controller
        );
    }

    public function getSocket(): Socket
    {
        return $this->socket;
    }

    public function getStateManager(): Manager
    {
        return $this->stateManager;
    }

    public function getController(): ?FlowController
    {
        return $this->controller;
    }

    public function getState(): ConnectionState
    {
        return $this->stateManager->getCurrentState();
    }

    public function getHandshakeState(): HandshakeState
    {
        return $this->stateManager->getHandshakeState();
    }

    // === Data Transfer ===

    public function send(string $data): void
    {
        if (!$this->stateManager->isConnected()) {
            throw new StateException("Cannot send data: connection not established");
        }

        $record = Builder::applicationData($data);
        $this->recordLayer->sendRecord($record);

        $this->stateManager->getTrafficState()->incrementWriteSequence();
    }

    public function receive(int $maxLength = 8192): ?string
    {
        if (!$this->stateManager->isConnected()) {
            throw new StateException("Cannot receive data: connection not established");
        }

        $record = $this->recordLayer->receiveRecord();
        if (!$record) {
            return null;
        }

        if ($record->contentType === ContentType::APPLICATION_DATA) {
            $this->stateManager->getTrafficState()->incrementReadSequence();
            return substr($record->payload, 0, $maxLength);
        }

        $this->handleNonApplicationRecord($record);
        return null;
    }

    // === Protocol Control ===

    public function sendKeyUpdate(bool $requestUpdate = false): void
    {
        if (!$this->stateManager->isConnected()) {
            throw new StateException("Cannot send KeyUpdate: connection not established");
        }

        $keyUpdate = new KeyUpdate($requestUpdate);
        $record = Builder::handshake($keyUpdate->toWire());
        $this->recordLayer->sendRecord($record);

        $this->stateManager->getTrafficState()->scheduleKeyUpdate();
    }

    public function sendAlert(AlertLevel $level, AlertDescription $description): void
    {
        $alertData = $level->toByte() . $description->toByte();
        $record = Builder::alert($alertData);
        $this->recordLayer->sendRecord($record);

        if ($description->isFatal()) {
            $this->stateManager->error("sent_fatal_alert_{$description->name}");
        }
    }

    public function abruptClose(): void
    {
        $this->stateManager->close(true);
        $this->socket->close();
    }

    public function gracefulClose(): void
    {
        if ($this->stateManager->isConnected()) {
            $this->sendAlert(AlertLevel::WARNING, AlertDescription::CLOSE_NOTIFY);
        }

        $this->stateManager->close(false);
        $this->socket->close();
    }

    // === Testing Helpers ===

    public function fragmentNextRecord(int $maxFragmentSize): void
    {
        $this->recordLayer->enableFragmentation($maxFragmentSize);
    }

    public function delayNextRecord(float $seconds): void
    {
        if ($this->controller) {
            $this->controller->setGlobalDelay($seconds);
        }
    }

    public function waitForHandshakeCompletion(float $timeout = 30.0): bool
    {
        $startTime = microtime(true);

        while (!$this->stateManager->isHandshakeComplete()) {
            if (microtime(true) - $startTime > $timeout) {
                return false;
            }

            $record = $this->recordLayer->receiveRecord();
            if ($record) {
                $this->handleNonApplicationRecord($record);
            }

            usleep(10000);
        }

        return true;
    }

    // === Internal Methods ===

    public function handleNonApplicationRecord(Record $record): void
    {
        switch ($record->contentType) {
            case ContentType::HANDSHAKE:
                $this->handleHandshakeRecord($record);
                break;

            case ContentType::ALERT:
                $this->handleAlertRecord($record);
                break;

            case ContentType::CHANGE_CIPHER_SPEC:
                // Ignore in TLS 1.3 (compatibility)
                break;
        }
    }

    private function handleHandshakeRecord(Record $record): void
    {
        try {
            $offset = 0;
            $message = HandshakeMessage::fromWire($record->payload, $offset);
            $this->stateManager->processHandshakeMessage($message);
        } catch (CraftException $e) {
            $this->stateManager->error("malformed_handshake: " . $e->getMessage());
        }
    }

    private function handleAlertRecord(Record $record): void
    {
        if (strlen($record->payload) >= 2) {
            $level = AlertLevel::fromByte($record->payload[0]);
            $description = AlertDescription::fromByte($record->payload[1]);

            if ($description === AlertDescription::CLOSE_NOTIFY) {
                $this->stateManager->close(false);
            } elseif ($description->isFatal()) {
                $this->stateManager->error("received_fatal_alert_{$description->name}");
            }
        }
    }
}