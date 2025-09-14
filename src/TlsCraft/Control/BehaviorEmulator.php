<?php

namespace Php\TlsCraft\Control;

use Php\TlsCraft\Protocol\ContentType;
use Php\TlsCraft\Record\Record;
use Php\TlsCraft\State\ConnectionState;
use Php\TlsCraft\State\Manager;

class BehaviorEmulator
{
    public static function brokenClient(Manager $stateManager): FlowController
    {
        $controller = new FlowController($stateManager);

        // Randomly drop handshake messages
        $controller->dropRecords(ContentType::HANDSHAKE, 1);

        // Send application data before handshake completes
        $controller->onStateChange(function($old, $new) use ($controller) {
            if ($new === ConnectionState::HANDSHAKING) {
                $controller->scheduleAction(0.1, function() {
                    // This would send application data during handshake
                }, "premature_app_data");
            }
        });

        return $controller;
    }

    public static function slowClient(Manager $stateManager, int $bytesPerSecond): FlowController
    {
        $controller = new FlowController($stateManager);

        // Calculate delay per record based on throughput
        $delayPerKB = 1024.0 / $bytesPerSecond;

        $controller->addRecordDelay(ContentType::APPLICATION_DATA, $delayPerKB);
        $controller->addRecordDelay(ContentType::HANDSHAKE, $delayPerKB * 0.5);

        return $controller;
    }

    public static function aggressiveKeyUpdater(Manager $stateManager): FlowController
    {
        $controller = new FlowController($stateManager);

        // Schedule multiple key updates in rapid succession
        $controller->onStateChange(function($old, $new) use ($controller) {
            if ($new === ConnectionState::CONNECTED) {
                for ($i = 1; $i <= 5; $i++) {
                    $controller->scheduleKeyUpdate($i * 0.5, true);
                }
            }
        });

        return $controller;
    }

    public static function abruptCloser(Manager $stateManager): FlowController
    {
        $controller = new FlowController($stateManager);

        // Close connection abruptly after sending some data
        $controller->onStateChange(function($old, $new) use ($controller) {
            if ($new === ConnectionState::CONNECTED) {
                $controller->scheduleAbruptClose(2.0);
            }
        });

        return $controller;
    }

    public static function fragmentingClient(Manager $stateManager, int $fragmentSize = 100): FlowController
    {
        $controller = new FlowController($stateManager);

        // Fragment all records to very small sizes
        $controller->enableRecordFragmentation($fragmentSize);

        // Add delays between fragments
        $controller->addRecordDelay(ContentType::APPLICATION_DATA, 0.1);

        return $controller;
    }

    public static function stateViolator(Manager $stateManager): FlowController
    {
        $controller = new FlowController($stateManager);

        // Attempt invalid state transitions
        $controller->onStateChange(function($old, $new) use ($controller, $stateManager) {
            if ($new === ConnectionState::HANDSHAKING) {
                // Try to force immediate connection without completing handshake
                $controller->scheduleStateTransition(0.1, ConnectionState::CONNECTED);
            }
        });

        return $controller;
    }

    public static function maliciousClient(Manager $stateManager): FlowController
    {
        $controller = new FlowController($stateManager);

        // Corrupt handshake messages
        $controller->corruptRecord(ContentType::HANDSHAKE, 0, 0xFF);

        // Send oversized records
        $controller->onRecordSent(function(Record $record) {
            if ($record->contentType === ContentType::APPLICATION_DATA) {
                // This would create an oversized record in practice
                return $record;
            }
            return $record;
        });

        // Random delays to cause timeouts
        $controller->enableJitter(2.0);

        return $controller;
    }

    public static function custom(): FlowController
    {
        // Returns a basic controller for custom configuration
        return new FlowController(new Manager());
    }
}