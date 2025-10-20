<?php

namespace Php\TlsCraft\Handshake\Processors;

use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Handshake\Messages\Finished;

class FinishedProcessor extends MessageProcessor
{
    public function process(Finished $message): void
    {
        // Verify the Finished message
        $this->verifyFinishedData($message->verifyData);

        // Update state to indicate handshake is complete
        $this->context->setHandshakeComplete(true);
    }

    private function verifyFinishedData(string $receivedVerifyData): void
    {
        // Get the hash algorithm from negotiated cipher suite
        $cipherSuite = $this->context->getNegotiatedCipherSuite();
        if (!$cipherSuite) {
            throw new ProtocolViolationException('No cipher suite negotiated');
        }
        $hashAlgorithm = $cipherSuite->getHashAlgorithm();

        // Get the key schedule
        $keySchedule = $this->context->getKeySchedule();
        if (!$keySchedule) {
            throw new ProtocolViolationException('Key schedule not initialized');
        }

        // Get transcript hash excluding the Finished message itself
        $transcriptHash = $this->context->getTranscriptHash($hashAlgorithm, 0, -1);

        // Get the appropriate handshake traffic secret
        if ($this->context->isClient()) {
            // We're client verifying server's Finished
            $handshakeSecret = $keySchedule->getServerHandshakeTrafficSecret();
        } else {
            // We're server verifying client's Finished
            $handshakeSecret = $keySchedule->getClientHandshakeTrafficSecret();
        }

        // Derive the finished_key from the handshake traffic secret
        $finishedKey = $keySchedule->getFinishedKey($handshakeSecret);

        // Compute the expected verify_data
        $expectedVerifyData = hash_hmac($hashAlgorithm, $transcriptHash, $finishedKey, true);

        // Compare with received verify_data using constant-time comparison
        if (!hash_equals($expectedVerifyData, $receivedVerifyData)) {
            throw new ProtocolViolationException('Finished message verification failed - HMAC mismatch');
        }
    }
}

