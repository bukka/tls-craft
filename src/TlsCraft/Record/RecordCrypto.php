<?php

namespace Php\TlsCraft\Record;

use Php\TlsCraft\Context;
use Php\TlsCraft\Crypto\AEAD;
use Php\TlsCraft\Protocol\ContentType;

class RecordCrypto
{
    private Context $context;
    private ?AEAD $readCipher = null;
    private ?AEAD $writeCipher = null;
    private int $readSequence = 0;
    private int $writeSequence = 0;

    public function __construct(Context $context)
    {
        $this->context = $context;
    }

    /**
     * Encrypt a record for transmission
     */
    public function encryptRecord(Record $record): Record
    {
        if (!$this->context->getKeySchedule() || !$this->shouldEncrypt()) {
            return $record; // Return unencrypted during handshake
        }

        if (!$this->writeCipher) {
            $this->initializeWriteCipher();
        }

        // TLS 1.3 record encryption
        $innerPlaintext = $record->payload . chr($record->contentType->value);
        $additionalData = $this->createAAD(ContentType::APPLICATION_DATA, strlen($innerPlaintext) + 16);

        $ciphertext = $this->writeCipher->encrypt(
            $innerPlaintext,
            $additionalData,
            $this->writeSequence++
        );

        return new Record(
            ContentType::APPLICATION_DATA, // TLS 1.3 hides real content type
            $record->version,
            $ciphertext
        );
    }

    /**
     * Decrypt a received record
     */
    public function decryptRecord(Record $record): Record
    {
        if (!$this->context->getKeySchedule() || !$this->shouldEncrypt()) {
            return $record; // Return as-is during handshake
        }

        if (!$this->readCipher) {
            $this->initializeReadCipher();
        }

        $additionalData = $this->createAAD($record->contentType, strlen($record->payload));

        $plaintext = $this->readCipher->decrypt(
            $record->payload,
            $additionalData,
            $this->readSequence++
        );

        // Extract real content type from end of plaintext (TLS 1.3)
        $realContentType = ContentType::from(ord($plaintext[-1]));
        $messageData = substr($plaintext, 0, -1);

        return new Record(
            $realContentType,
            $record->version,
            $messageData
        );
    }

    /**
     * Check if we should encrypt records (after handshake keys are established)
     */
    private function shouldEncrypt(): bool
    {
        $keySchedule = $this->context->getKeySchedule();
        return $keySchedule && $keySchedule->hasHandshakeKeys();
    }

    private function initializeWriteCipher(): void
    {
        $keys = $this->context->getHandshakeKeys($this->context->isClient());
        $this->writeCipher = new AEAD($keys['key'], $keys['iv']);
    }

    private function initializeReadCipher(): void
    {
        $keys = $this->context->getHandshakeKeys(!$this->context->isClient());
        $this->readCipher = new AEAD($keys['key'], $keys['iv']);
    }

    private function createAAD(ContentType $contentType, int $length): string
    {
        return pack('Cnn', $contentType->value, $this->context->getNegotiatedVersion()->value, $length);
    }

    /**
     * Update traffic keys after KeyUpdate
     */
    public function updateTrafficKeys(): void
    {
        $this->context->updateTrafficKeys();

        // Re-initialize ciphers with new keys
        $this->readCipher = null;
        $this->writeCipher = null;
        // They will be re-initialized on next use
    }
}