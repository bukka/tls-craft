<?php

namespace Php\TlsCraft\Handshake\Processors;

use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Handshake\Messages\FinishedMessage;
use Php\TlsCraft\Protocol\HandshakeType;

class FinishedProcessor extends MessageProcessor
{
    public function process(FinishedMessage $message): void
    {
        // Verify the FinishedMessage message
        $this->verifyFinishedData($message->verifyData);
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

        // Get transcript hash including all messages except the server Finished
        $transcriptHash = $this->context->getHandshakeTranscript()->getHashAllExceptLast(
            $cipherSuite->getHashAlgorithm(),
        );

        // Get the appropriate handshake traffic secret
        if ($this->context->isClient()) {
            $handshakeSecret = $keySchedule->getServerHandshakeTrafficSecret();
        } else {
            $handshakeSecret = $keySchedule->getClientHandshakeTrafficSecret();
        }

        // Derive the finished_key from the handshake traffic secret
        $finishedKey = $keySchedule->getFinishedKey($handshakeSecret);

        // Compute the expected verify_data
        $expectedVerifyData = hash_hmac($hashAlgorithm, $transcriptHash, $finishedKey, true);

        // Compare with received verify_data using constant-time comparison
        if (!hash_equals($expectedVerifyData, $receivedVerifyData)) {
            throw new ProtocolViolationException('FinishedMessage message verification failed - HMAC mismatch');
        }
    }
}
