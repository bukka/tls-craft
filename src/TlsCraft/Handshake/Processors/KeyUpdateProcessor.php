<?php

namespace Php\TlsCraft\Messages\Processors;

use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Messages\KeyUpdate;

class KeyUpdateProcessor extends MessageProcessor
{
    public function process(KeyUpdate $message): void
    {
        // Validate that handshake is complete before processing KeyUpdate
        if (!$this->context->isHandshakeComplete()) {
            throw new ProtocolViolationException(
                "KeyUpdate received before handshake completion"
            );
        }

        // KeyUpdate is NOT added to handshake transcript (post-handshake message)
        // Unlike other handshake messages, KeyUpdate doesn't affect transcript

        // Update the peer's traffic keys (keys we use to decrypt their messages)
        $this->updatePeerTrafficKeys();

        // If peer requested key update, we need to update our own keys and respond
        if ($message->requestUpdate) {
            $this->updateOwnTrafficKeys();
            $this->context->setKeyUpdateResponseRequired(true);
        }
    }

    private function updatePeerTrafficKeys(): void
    {
        $keySchedule = $this->context->getKeySchedule();
        if (!$keySchedule) {
            throw new ProtocolViolationException(
                "Key schedule not available for key update"
            );
        }

        // Get current peer traffic secret and update it
        if ($this->context->isClient()) {
            // Client updating server's keys (for decrypting server messages)
            $currentSecret = $keySchedule->getServerApplicationTrafficSecret();
            $newSecret = $keySchedule->updateTrafficSecret($currentSecret);
            $this->context->setServerApplicationTrafficSecret($newSecret);
        } else {
            // Server updating client's keys (for decrypting client messages)
            $currentSecret = $keySchedule->getClientApplicationTrafficSecret();
            $newSecret = $keySchedule->updateTrafficSecret($currentSecret);
            $this->context->setClientApplicationTrafficSecret($newSecret);
        }

        // Derive new decryption keys from updated secret
        $this->updateDecryptionKeys();
    }

    private function updateOwnTrafficKeys(): void
    {
        $keySchedule = $this->context->getKeySchedule();

        // Update our own traffic secret (for encrypting our messages)
        if ($this->context->isClient()) {
            // Client updating own keys (for encrypting client messages)
            $currentSecret = $keySchedule->getClientApplicationTrafficSecret();
            $newSecret = $keySchedule->updateTrafficSecret($currentSecret);
            $this->context->setClientApplicationTrafficSecret($newSecret);
        } else {
            // Server updating own keys (for encrypting server messages)
            $currentSecret = $keySchedule->getServerApplicationTrafficSecret();
            $newSecret = $keySchedule->updateTrafficSecret($currentSecret);
            $this->context->setServerApplicationTrafficSecret($newSecret);
        }

        // Derive new encryption keys from updated secret
        $this->updateEncryptionKeys();
    }

    private function updateDecryptionKeys(): void
    {
        $keySchedule = $this->context->getKeySchedule();

        // Get the updated peer secret
        $peerSecret = $this->context->isClient()
            ? $this->context->getServerApplicationTrafficSecret()
            : $this->context->getClientApplicationTrafficSecret();

        // Derive new keys for decryption
        $newKeys = $keySchedule->deriveApplicationKeys($peerSecret);

        // Update the decryption context
        $this->context->updateDecryptionKeys($newKeys['key'], $newKeys['iv']);

        // Reset sequence number for new keys
        $this->context->resetReadSequenceNumber();
    }

    private function updateEncryptionKeys(): void
    {
        $keySchedule = $this->context->getKeySchedule();

        // Get our updated secret
        $ownSecret = $this->context->isClient()
            ? $this->context->getClientApplicationTrafficSecret()
            : $this->context->getServerApplicationTrafficSecret();

        // Derive new keys for encryption
        $newKeys = $keySchedule->deriveApplicationKeys($ownSecret);

        // Update the encryption context
        $this->context->updateEncryptionKeys($newKeys['key'], $newKeys['iv']);

        // Reset sequence number for new keys
        $this->context->resetWriteSequenceNumber();
    }
}
