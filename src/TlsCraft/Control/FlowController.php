<?php

namespace Php\TlsCraft\Control;

use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Protocol\AlertDescription;
use Php\TlsCraft\Protocol\AlertLevel;
use Php\TlsCraft\Protocol\ContentType;
use Php\TlsCraft\Record\Record;
use Php\TlsCraft\State\ConnectionState;
use Php\TlsCraft\State\Manager;

class FlowController
{
    private Manager $stateManager;
    private Timing $timing;

    /** @var ScheduledAction[] */
    private array $scheduledActions = [];
    private float $startTime;
    private array $recordInterceptions = [];
    private bool $fragmentationEnabled = false;
    private int $maxFragmentSize = 1024;
    private array $corruptionRules = [];
    private array $dropRules = [];

    public function __construct(Manager $stateManager)
    {
        $this->stateManager = $stateManager;
        $this->timing = new Timing();
        $this->startTime = microtime(true);

        // Listen for state changes to execute scheduled actions
        $this->stateManager->onStateChange([$this, 'onStateChange']);
    }

    public function getStateManager(): Manager
    {
        return $this->stateManager;
    }

    // === Scheduling Actions ===

    public function scheduleKeyUpdate(float $afterSeconds, bool $requestUpdate = false): self
    {
        $this->scheduleAction($afterSeconds, function() use ($requestUpdate) {
            $this->triggerKeyUpdate($requestUpdate);
        }, "key_update");

        return $this;
    }

    public function scheduleAbruptClose(float $afterSeconds): self
    {
        $this->scheduleAction($afterSeconds, function() {
            $this->triggerAbruptClose();
        }, "abrupt_close");

        return $this;
    }

    public function scheduleAlert(float $afterSeconds, AlertLevel $level, AlertDescription $description): self
    {
        $this->scheduleAction($afterSeconds, function() use ($level, $description) {
            $this->triggerAlert($level, $description);
        }, "alert_{$description->name}");

        return $this;
    }

    public function scheduleStateTransition(float $afterSeconds, ConnectionState $newState): self
    {
        $this->scheduleAction($afterSeconds, function() use ($newState) {
            $this->stateManager->transition($newState, 'scheduled_transition');
        }, "state_transition_{$newState->value}");

        return $this;
    }

    public function scheduleAction(float $afterSeconds, callable $action, string $description): void
    {
        $executeAt = $this->startTime + $afterSeconds;
        $this->scheduledActions[] = new ScheduledAction($executeAt, $action, $description);
    }

    // === Timing Control ===

    public function addRecordDelay(ContentType $type, float $seconds): self
    {
        $this->timing->addRecordDelay($type, $seconds);
        return $this;
    }

    public function addStateTransitionDelay(ConnectionState $state, float $seconds): self
    {
        $this->timing->addStateDelay($state, $seconds);
        return $this;
    }

    public function setGlobalDelay(float $seconds): self
    {
        $this->timing->setGlobalDelay($seconds);
        return $this;
    }

    public function enableJitter(float $maxJitter): self
    {
        $this->timing->enableJitter($maxJitter);
        return $this;
    }

    // === Record Manipulation ===

    public function enableRecordFragmentation(int $maxSize): self
    {
        $this->fragmentationEnabled = true;
        $this->maxFragmentSize = min($maxSize, Record::MAX_PAYLOAD_LENGTH);
        return $this;
    }

    public function disableRecordFragmentation(): self
    {
        $this->fragmentationEnabled = false;
        return $this;
    }

    public function corruptRecord(ContentType $type, int $bytePosition, int $newValue): self
    {
        $this->corruptionRules[] = [
            'type' => $type,
            'position' => $bytePosition,
            'value' => $newValue
        ];
        return $this;
    }

    public function dropRecords(ContentType $type, int $count = 1): self
    {
        $this->dropRules[] = [
            'type' => $type,
            'count' => $count,
            'dropped' => 0
        ];
        return $this;
    }

    // === Callback Registration ===

    public function onStateChange(callable $callback): self
    {
        $this->stateManager->onStateChange($callback);
        return $this;
    }

    public function onRecordSent(callable $callback): self
    {
        $this->recordInterceptions['send'][] = $callback;
        return $this;
    }

    public function onRecordReceived(callable $callback): self
    {
        $this->recordInterceptions['receive'][] = $callback;
        return $this;
    }

    // === RecordInterceptor Implementation ===

    public function beforeSend(Record $record): Record
    {
        $this->executeScheduledActions();

        // Apply custom send callbacks
        foreach ($this->recordInterceptions['send'] ?? [] as $callback) {
            $record = $callback($record) ?? $record;
        }

        // Apply corruption rules
        foreach ($this->corruptionRules as $rule) {
            if ($rule['type'] === $record->contentType) {
                try {
                    $record = $record->withCorruption($rule['position'], $rule['value']);
                } catch (CraftException $e) {
                    // Ignore corruption if position is invalid
                }
            }
        }

        return $record;
    }

    public function afterReceive(Record $record): Record
    {
        $this->executeScheduledActions();

        // Apply custom receive callbacks
        foreach ($this->recordInterceptions['receive'] ?? [] as $callback) {
            $record = $callback($record) ?? $record;
        }

        return $record;
    }

    public function shouldDrop(Record $record): bool
    {
        foreach ($this->dropRules as &$rule) {
            if ($rule['type'] === $record->contentType && $rule['dropped'] < $rule['count']) {
                $rule['dropped']++;
                return true;
            }
        }
        return false;
    }

    public function getDelay(Record $record): float
    {
        return $this->timing->getRecordDelay($record->contentType);
    }

    public function shouldFragment(Record $record): ?int
    {
        if ($this->fragmentationEnabled && $record->getLength() > $this->maxFragmentSize) {
            return $this->maxFragmentSize;
        }
        return null;
    }

    // === Internal Methods ===

    private function executeScheduledActions(): void
    {
        $currentTime = microtime(true);

        foreach ($this->scheduledActions as $key => $action) {
            if ($action->shouldExecute($currentTime)) {
                try {
                    $action->execute();
                } catch (\Throwable $e) {
                    // Log error but continue
                    error_log("Scheduled action failed: " . $e->getMessage());
                }
                unset($this->scheduledActions[$key]);
            }
        }
    }

    public function handleStateChange(ConnectionState $oldState, ConnectionState $newState, ?string $reason): void
    {
        // Apply state transition delays
        $delay = $this->timing->getStateDelay($newState);
        if ($delay > 0) {
            $this->timing->applyDelay($delay);
        }

        $this->executeScheduledActions();
    }

    private function triggerKeyUpdate(bool $requestUpdate): void
    {
        if ($this->stateManager->isConnected()) {
            $this->stateManager->getTrafficState()->scheduleKeyUpdate();
            // In a real implementation, this would send a KeyUpdate message
        }
    }

    private function triggerAbruptClose(): void
    {
        $this->stateManager->close(true);
    }

    private function triggerAlert(AlertLevel $level, AlertDescription $description): void
    {
        if ($description->isFatal()) {
            $this->stateManager->error("alert_{$description->name}");
        }
        // In a real implementation, this would send an Alert message
    }
}