<?php

namespace Php\TlsCraft\Handshake\Processors;

use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Handshake\Messages\Finished;

class FinishedProcessor extends MessageProcessor
{
    public function process(Finished $message): void
    {
        // Verify the Finished message HMAC
        $this->verifyFinishedData($message->verifyData);

        // Derive application traffic secrets if not already done
        if (!$this->context->hasApplicationSecrets()) {
            $this->context->deriveApplicationSecrets();
        }
    }

    private function verifyFinishedData(string $receivedVerifyData): void
    {
        // Calculate expected Finished data
        $expectedVerifyData = $this->calculateFinishedData();

        // Constant-time comparison to prevent timing attacks
        if (!hash_equals($expectedVerifyData, $receivedVerifyData)) {
            throw new ProtocolViolationException('Finished message verification failed - HMAC mismatch');
        }
    }

    private function calculateFinishedData(): string
    {
        $keySchedule = $this->context->getKeySchedule();
        if (!$keySchedule) {
            throw new ProtocolViolationException('Key schedule not available for Finished verification');
        }

        // Get the appropriate traffic secret for the peer
        $peerIsClient = !$this->context->isClient();
        $trafficSecret = $peerIsClient
            ? $keySchedule->getClientHandshakeTrafficSecret()
            : $keySchedule->getServerHandshakeTrafficSecret();

        // Derive the finished key
        $finishedKey = $keySchedule->getFinishedKey($trafficSecret);

        // Calculate the verify data
        return $keySchedule->calculateFinishedData($finishedKey);
    }
}
