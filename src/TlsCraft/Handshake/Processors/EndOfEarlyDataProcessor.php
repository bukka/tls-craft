<?php

namespace Php\TlsCraft\Handshake\Processors;

use Php\TlsCraft\Handshake\Messages\EndOfEarlyDataMessage;
use Php\TlsCraft\Logger;

/**
 * Processor for EndOfEarlyData messages (server-side)
 *
 * When the server receives EndOfEarlyData, it indicates that:
 * 1. The client has finished sending 0-RTT data
 * 2. The server should switch from early_traffic_keys to handshake_keys
 *    for decrypting subsequent client messages
 */
class EndOfEarlyDataProcessor extends MessageProcessor
{
    public function process(EndOfEarlyDataMessage $message): void
    {
        Logger::debug('Processing EndOfEarlyData');

        // Verify we were expecting early data
        if (!$this->context->isEarlyDataAccepted()) {
            Logger::warning('Received EndOfEarlyData but early data was not accepted');
            // This could be a protocol violation, but we'll handle it gracefully
        }

        // The server needs to:
        // 1. Stop accepting early data
        // 2. Switch decryption keys from early_traffic to handshake_traffic

        // Note: The actual key switch is handled by the ProtocolOrchestrator
        // or EncryptedLayer based on the current state

        Logger::debug('EndOfEarlyData processed, ready to receive client handshake messages');
    }
}
