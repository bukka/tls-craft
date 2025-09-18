<?php

namespace Php\TlsCraft\Control;

use Php\TlsCraft\Protocol\AlertDescription;
use Php\TlsCraft\Protocol\AlertLevel;
use Php\TlsCraft\Protocol\ContentType;
use Php\TlsCraft\State\ConnectionState;
use Php\TlsCraft\State\StateTracker;

class BehaviorEmulator
{
    public static function brokenClient(StateTracker $stateTracker): FlowController
    {
        $controller = new FlowController($stateTracker);

        // Randomly drop handshake messages
        $controller->dropRecords(ContentType::HANDSHAKE, 1);

        // Send alert when handshaking starts
        $controller->addEventListener('state_change', function (ControlEvent $event) use ($controller) {
            if ($event->data['new_state'] === ConnectionState::HANDSHAKING) {
                $controller->scheduleAlert(0.1, AlertLevel::FATAL, AlertDescription::INTERNAL_ERROR);
            }
        });

        return $controller;
    }

    public static function slowClient(StateTracker $stateTracker, int $bytesPerSecond): FlowController
    {
        $controller = new FlowController($stateTracker);

        // Calculate delay per record based on throughput
        $delayPerKB = 1024.0 / $bytesPerSecond;

        $controller->addRecordDelay(ContentType::APPLICATION_DATA, $delayPerKB);
        $controller->addRecordDelay(ContentType::HANDSHAKE, $delayPerKB * 0.5);

        return $controller;
    }

    public static function aggressiveKeyUpdater(StateTracker $stateTracker): FlowController
    {
        $controller = new FlowController($stateTracker);

        // Schedule multiple key updates when connected
        $controller->addEventListener('state_change', function (ControlEvent $event) use ($controller) {
            if ($event->data['new_state'] === ConnectionState::CONNECTED) {
                for ($i = 1; $i <= 5; ++$i) {
                    $controller->scheduleKeyUpdate($i * 0.5, true);
                }
            }
        });

        return $controller;
    }

    public static function abruptCloser(StateTracker $stateTracker): FlowController
    {
        $controller = new FlowController($stateTracker);

        // Close connection abruptly after connecting
        $controller->addEventListener('state_change', function (ControlEvent $event) use ($controller) {
            if ($event->data['new_state'] === ConnectionState::CONNECTED) {
                $controller->scheduleAbruptClose(2.0);
            }
        });

        return $controller;
    }

    public static function fragmentingClient(StateTracker $stateTracker, int $fragmentSize = 100): FlowController
    {
        $controller = new FlowController($stateTracker);

        // Fragment all records to very small sizes
        $controller->enableRecordFragmentation($fragmentSize);

        // Add delays between fragments
        $controller->addRecordDelay(ContentType::APPLICATION_DATA, 0.1);

        return $controller;
    }

    public static function stateViolator(StateTracker $stateTracker): FlowController
    {
        $controller = new FlowController($stateTracker);

        // Trigger events that attempt protocol violations
        $controller->addEventListener('state_change', function (ControlEvent $event) use ($controller) {
            if ($event->data['new_state'] === ConnectionState::HANDSHAKING) {
                // Try to send application data during handshake
                $controller->scheduleCustomEvent(0.1, 'send_app_data_early', ['data' => 'early data']);
            }
        });

        return $controller;
    }

    public static function maliciousClient(StateTracker $stateTracker): FlowController
    {
        $controller = new FlowController($stateTracker);

        // Corrupt handshake messages
        $controller->corruptRecord(ContentType::HANDSHAKE, 0, 0xFF);

        // Random delays to cause timeouts
        $controller->enableJitter(2.0);

        // Send malformed alerts
        $controller->addEventListener('state_change', function (ControlEvent $event) use ($controller) {
            if ($event->data['new_state'] === ConnectionState::CONNECTED) {
                $controller->scheduleAlert(1.0, AlertLevel::FATAL, AlertDescription::DECODE_ERROR);
            }
        });

        return $controller;
    }

    public static function custom(StateTracker $stateTracker): FlowController
    {
        // Returns a basic controller for custom configuration
        return new FlowController($stateTracker);
    }
}
