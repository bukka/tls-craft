<?php

namespace Php\TlsCraft\State;

use Php\TlsCraft\Protocol\HandshakeType;

/**
 * Validates protocol rules and message sequences
 */
class ProtocolValidator
{
    private bool $allowViolations;

    public function __construct(bool $allowViolations = false)
    {
        $this->allowViolations = $allowViolations;
    }

    public function validateHandshakeMessage(
        HandshakeType $messageType,
        HandshakeState $currentState,
        bool $isClient,
        bool $isResuming,
        bool $earlyDataAccepted = false,
    ): bool {
        if ($this->allowViolations) {
            return true;
        }

        $expectedTypes = $this->getExpectedMessageTypes($currentState, $isClient, $isResuming, $earlyDataAccepted);

        return in_array($messageType, $expectedTypes);
    }

    public function validateExtensionCombination(array $extensions): bool
    {
        if ($this->allowViolations) {
            return true;
        }

        // Check for duplicate extension types
        $types = [];
        foreach ($extensions as $extension) {
            if (in_array($extension->type, $types)) {
                return false; // Duplicate extension
            }
            $types[] = $extension->type;
        }

        // Validate specific extension rules (e.g., PSK must be last)
        return $this->validateExtensionOrder($extensions);
    }

    public function validateCipherSuiteSelection(array $clientSuites, int $serverChoice): bool
    {
        if ($this->allowViolations) {
            return true;
        }

        return in_array($serverChoice, $clientSuites);
    }

    private function getExpectedMessageTypes(
        HandshakeState $state,
        bool $isClient,
        bool $isResuming,
        bool $earlyDataAccepted,
    ): array {
        return match ($state) {
            HandshakeState::START => $isClient ?
                [HandshakeType::SERVER_HELLO] :
                [HandshakeType::CLIENT_HELLO],

            HandshakeState::WAIT_CLIENT_HELLO => [HandshakeType::CLIENT_HELLO],

            HandshakeState::WAIT_SERVER_HELLO => [HandshakeType::SERVER_HELLO],

            HandshakeState::WAIT_ENCRYPTED_EXTENSIONS => [HandshakeType::ENCRYPTED_EXTENSIONS],

            HandshakeState::WAIT_CERTIFICATE => $isResuming ?
                [HandshakeType::FINISHED] :
                (
                    $isClient ?
                    // Client can receive CertificateRequest (optional) or Certificate
                    [HandshakeType::CERTIFICATE_REQUEST, HandshakeType::CERTIFICATE] :
                    // Server only expects Certificate from client
                    [HandshakeType::CERTIFICATE]
                ),

            HandshakeState::WAIT_CERTIFICATE_VERIFY => [HandshakeType::CERTIFICATE_VERIFY],

            HandshakeState::WAIT_FINISHED => [HandshakeType::FINISHED],

            HandshakeState::WAIT_FLIGHT2 => $earlyDataAccepted ?
                // If early data was accepted, EndOfEarlyData comes before client's flight
                [
                    HandshakeType::END_OF_EARLY_DATA,
                    HandshakeType::CERTIFICATE,
                    HandshakeType::CERTIFICATE_VERIFY,
                    HandshakeType::FINISHED,
                ] :
                [
                    HandshakeType::CERTIFICATE,
                    HandshakeType::CERTIFICATE_VERIFY,
                    HandshakeType::FINISHED,
                ],

            // Server waiting specifically for EndOfEarlyData
            HandshakeState::WAIT_END_OF_EARLY_DATA => [HandshakeType::END_OF_EARLY_DATA],

            HandshakeState::CONNECTED => [HandshakeType::KEY_UPDATE, HandshakeType::NEW_SESSION_TICKET],
        };
    }

    private function validateExtensionOrder(array $extensions): bool
    {
        // PSK extension (type 41) must be last if present
        $pskPosition = -1;
        foreach ($extensions as $index => $extension) {
            if ($extension->type === 41) { // PSK extension
                $pskPosition = $index;
                break;
            }
        }

        if ($pskPosition !== -1 && $pskPosition !== count($extensions) - 1) {
            return false; // PSK not last
        }

        return true;
    }
}
