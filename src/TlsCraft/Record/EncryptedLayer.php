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
     * Activate early WRITE keys (client sending 0-RTT)
     */
    public function activateEarlyWriteKeys(): void
    {
        $this->crypto->activateEarlyWriteKeys();
    }

    /**
     * Activate early READ keys (server receiving 0-RTT)
     */
    public function activateEarlyReadKeys(): void
    {
        $this->crypto->activateEarlyReadKeys();
    }

    /**
     * Deactivate early WRITE keys
     */
    public function deactivateEarlyWriteKeys(): void
    {
        $this->crypto->deactivateEarlyWriteKeys();
    }

    /**
     * Deactivate early READ keys
     */
    public function deactivateEarlyReadKeys(): void
    {
        $this->crypto->deactivateEarlyReadKeys();
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
