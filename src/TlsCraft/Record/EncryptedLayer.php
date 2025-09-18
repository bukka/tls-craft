<?php

namespace Php\TlsCraft\Record;

use Php\TlsCraft\Context;

class EncryptedLayer
{
    private Layer $baseLayer;
    private RecordCrypto $crypto;

    public function __construct(
        Layer $baseLayer,
        Context $context
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

    /**
     * Update encryption keys
     */
    public function updateKeys(): void
    {
        $this->crypto->updateApplicationKeys();
    }

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