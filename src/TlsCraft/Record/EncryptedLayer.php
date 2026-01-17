<?php

namespace Php\TlsCraft\Record;

use Php\TlsCraft\Context;

class EncryptedLayer
{
    private Layer $baseLayer;
    private RecordCrypto $crypto;

    public function __construct(
        Layer $baseLayer,
        Context $context,
    ) {
        $this->baseLayer = $baseLayer;
        $this->crypto = new RecordCrypto($context);
    }

    /**
     * Send record with automatic encryption
     */
    public function sendRecord(Record $record): void
    {
        $encryptedRecord = $this->crypto->encryptRecord($record);
        $this->baseLayer->sendRecord($encryptedRecord);
    }

    /**
     * Receive record with automatic decryption
     */
    public function receiveRecord(): ?Record
    {
        $record = $this->baseLayer->receiveRecord();
        if (!$record) {
            return null;
        }

        return $this->crypto->decryptRecord($record);
    }

    // === Early Data Key Management ===

    /**
     * Activate early traffic keys for 0-RTT data
     */
    public function activateEarlyKeys(): void
    {
        $this->crypto->activateEarlyKeys();
    }

    /**
     * Deactivate early keys and switch to handshake keys
     */
    public function deactivateEarlyKeys(): void
    {
        $this->crypto->deactivateEarlyKeys();
    }

    /**
     * Check if early keys are currently active
     */
    public function hasEarlyKeysActive(): bool
    {
        return $this->crypto->hasEarlyKeysActive();
    }

    // === Application Key Management ===

    /**
     * Update encryption keys (for KeyUpdate)
     */
    public function updateKeys(): void
    {
        $this->crypto->updateApplicationKeys();
    }

    /**
     * Activate application keys after handshake
     */
    public function activateApplicationKeys(): void
    {
        $this->crypto->activateApplicationKeys();
    }

    // === Delegation Methods ===

    /**
     * Delegate other methods to base layer
     */
    public function setInterceptor(?RecordInterceptor $interceptor): void
    {
        $this->baseLayer->setInterceptor($interceptor);
    }

    public function enableFragmentation(int $maxSize): void
    {
        $this->baseLayer->enableFragmentation($maxSize);
    }

    public function disableFragmentation(): void
    {
        $this->baseLayer->disableFragmentation();
    }
}
