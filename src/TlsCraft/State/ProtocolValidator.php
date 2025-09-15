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

    public function validateHandshakeMessage(HandshakeType $messageType, HandshakeState $currentState, bool $isClient): bool
    {
        if ($this->allowViolations) {
            return true;
        }

        $expectedTypes = $this->getExpectedMessageTypes($currentState, $isClient);
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

    private function getExpectedMessageTypes(HandshakeState $state, bool $isClient): array
    {
        return match ($state) {
            HandshakeState::START => $isClient ?
                [HandshakeType::SERVER_HELLO] :
                [HandshakeType::CLIENT_HELLO],
            HandshakeState::WAIT_CLIENT_HELLO => [HandshakeType::CLIENT_HELLO],
            HandshakeState::WAIT_SERVER_HELLO => [HandshakeType::SERVER_HELLO],
            HandshakeState::WAIT_ENCRYPTED_EXTENSIONS => [HandshakeType::ENCRYPTED_EXTENSIONS],
            HandshakeState::WAIT_CERTIFICATE => [HandshakeType::CERTIFICATE],
            HandshakeState::WAIT_CERTIFICATE_VERIFY => [HandshakeType::CERTIFICATE_VERIFY],
            HandshakeState::WAIT_FINISHED => [HandshakeType::FINISHED],
            HandshakeState::WAIT_FLIGHT2 => [
                HandshakeType::CERTIFICATE,
                HandshakeType::CERTIFICATE_VERIFY,
                HandshakeType::FINISHED,
            ],
            HandshakeState::CONNECTED => [HandshakeType::KEY_UPDATE],
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
