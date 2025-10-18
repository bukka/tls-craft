<?php

namespace Php\TlsCraft\Record;

use Php\TlsCraft\Context;
use Php\TlsCraft\Crypto\Aead;
use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Protocol\ContentType;
use Php\TlsCraft\Protocol\Version;

class RecordCrypto
{
    private Context $context;

    // Handshake phase ciphers
    private ?Aead $handshakeReadCipher = null;
    private ?Aead $handshakeWriteCipher = null;
    private int $handshakeReadSequence = 0;
    private int $handshakeWriteSequence = 0;

    // Application phase ciphers
    private ?Aead $applicationReadCipher = null;
    private ?Aead $applicationWriteCipher = null;
    private int $applicationReadSequence = 0;
    private int $applicationWriteSequence = 0;

    public function __construct(Context $context)
    {
        $this->context = $context;
    }

    /**
     * Encrypt a record for transmission
     */
    public function encryptRecord(Record $record): Record
    {
        if (!$record->isEncrypted()) {
            return $record;
        }

        $keySchedule = $this->context->getKeySchedule();
        if (!$keySchedule) {
            throw new CraftException('Cannot encrypt record: key schedule not initialized');
        }

        // Determine which cipher to use based on handshake completion
        if ($this->context->hasApplicationSecrets()) {
            return $this->encryptWithApplicationKeys($record);
        } else {
            return $this->encryptWithHandshakeKeys($record);
        }
    }

    /**
     * Decrypt a received record
     */
    public function decryptRecord(Record $record): Record
    {
        // ChangeCipherSpec is never encrypted in TLS 1.3 (compatibility record)
        if ($record->contentType === ContentType::CHANGE_CIPHER_SPEC) {
            return $record;
        }

        // Don't decrypt plaintext handshake records (before encryption starts)
        if ($record->contentType === ContentType::HANDSHAKE && !$this->hasHandshakeKeys()) {
            return $record;
        }

        $keySchedule = $this->context->getKeySchedule();
        if (!$keySchedule) {
            return $record; // Return as-is during early handshake
        }

        // Determine which cipher to use based on handshake completion
        if ($this->context->hasApplicationSecrets()) {
            return $this->decryptWithApplicationKeys($record);
        } else {
            return $this->decryptWithHandshakeKeys($record);
        }
    }

    /**
     * Update to application traffic keys after handshake completion
     */
    public function activateApplicationKeys(): void
    {
        $this->applicationReadCipher = null;  // Will be initialized on first use
        $this->applicationWriteCipher = null;
        $this->applicationReadSequence = 0;
        $this->applicationWriteSequence = 0;
    }

    /**
     * Update traffic keys after KeyUpdate message
     */
    public function updateApplicationKeys(): void
    {
        if (!$this->context->hasApplicationSecrets()) {
            throw new CraftException('Cannot update keys: application secrets not available');
        }

        // Get current traffic secrets
        $clientSecret = $this->context->getClientApplicationTrafficSecret();
        $serverSecret = $this->context->getServerApplicationTrafficSecret();

        // Update them using KeySchedule
        $keySchedule = $this->context->getKeySchedule();
        $newClientSecret = $keySchedule->updateTrafficSecret($clientSecret);
        $newServerSecret = $keySchedule->updateTrafficSecret($serverSecret);

        // Store updated secrets back
        $this->context->setClientApplicationTrafficSecret($newClientSecret);
        $this->context->setServerApplicationTrafficSecret($newServerSecret);

        // Reset sequence numbers and ciphers (will reinitialize with new keys)
        $this->applicationReadCipher = null;
        $this->applicationWriteCipher = null;
        $this->applicationReadSequence = 0;
        $this->applicationWriteSequence = 0;
    }

    private function encryptWithHandshakeKeys(Record $record): Record
    {
        if (!$this->handshakeWriteCipher) {
            $this->initializeHandshakeWriteCipher();
        }

        $innerPlaintext = $record->payload.chr($record->contentType->value);
        $additionalData = $this->createAAD(ContentType::APPLICATION_DATA, strlen($innerPlaintext) + 16);

        $ciphertext = $this->handshakeWriteCipher->encrypt(
            $innerPlaintext,
            $additionalData,
            $this->handshakeWriteSequence++,
        );

        return new Record(
            ContentType::APPLICATION_DATA, // TLS 1.3 hides real content type
            $record->version,
            $ciphertext,
        );
    }

    private function encryptWithApplicationKeys(Record $record): Record
    {
        if (!$this->applicationWriteCipher) {
            $this->initializeApplicationWriteCipher();
        }

        $innerPlaintext = $record->payload.chr($record->contentType->value);
        $additionalData = $this->createAAD(ContentType::APPLICATION_DATA, strlen($innerPlaintext) + 16);

        $ciphertext = $this->applicationWriteCipher->encrypt(
            $innerPlaintext,
            $additionalData,
            $this->applicationWriteSequence++,
        );

        return new Record(
            ContentType::APPLICATION_DATA,
            $record->version,
            $ciphertext,
        );
    }

    private function decryptWithHandshakeKeys(Record $record): Record
    {
        if (!$this->handshakeReadCipher) {
            $this->initializeHandshakeReadCipher();
        }

        $additionalData = $this->createAAD($record->contentType, strlen($record->payload));

        $plaintext = $this->handshakeReadCipher->decrypt(
            $record->payload,
            $additionalData,
            $this->handshakeReadSequence++,
        );

        return $this->extractInnerRecord($plaintext, $record->version);
    }

    private function decryptWithApplicationKeys(Record $record): Record
    {
        if (!$this->applicationReadCipher) {
            $this->initializeApplicationReadCipher();
        }

        $additionalData = $this->createAAD($record->contentType, strlen($record->payload));

        $plaintext = $this->applicationReadCipher->decrypt(
            $record->payload,
            $additionalData,
            $this->applicationReadSequence++,
        );

        return $this->extractInnerRecord($plaintext, $record->version);
    }

    private function extractInnerRecord(string $plaintext, $version): Record
    {
        // Extract real content type from end of plaintext (TLS 1.3)
        $realContentType = ContentType::from(ord($plaintext[-1]));
        $messageData = substr($plaintext, 0, -1);

        return new Record($realContentType, $version, $messageData);
    }

    private function hasHandshakeKeys(): bool
    {
        $keySchedule = $this->context->getKeySchedule();

        return $keySchedule && method_exists($keySchedule, 'hasHandshakeKeys')
            ? $keySchedule->hasHandshakeKeys()
            : false;
    }

    private function initializeHandshakeWriteCipher(): void
    {
        $keys = $this->context->getHandshakeKeys($this->context->isClient());
        $cipherSuite = $this->context->getNegotiatedCipherSuite();
        $this->handshakeWriteCipher = $this->context->getCryptoFactory()
            ->createAead($keys['key'], $keys['iv'], $cipherSuite);
    }

    private function initializeHandshakeReadCipher(): void
    {
        $keys = $this->context->getHandshakeKeys(!$this->context->isClient());
        $cipherSuite = $this->context->getNegotiatedCipherSuite();
        $this->handshakeReadCipher = $this->context->getCryptoFactory()
            ->createAead($keys['key'], $keys['iv'], $cipherSuite);
    }

    private function initializeApplicationWriteCipher(): void
    {
        $keys = $this->context->getApplicationKeys($this->context->isClient());
        $cipherSuite = $this->context->getNegotiatedCipherSuite();
        $this->applicationWriteCipher = $this->context->getCryptoFactory()
            ->createAead($keys['key'], $keys['iv'], $cipherSuite);
    }

    private function initializeApplicationReadCipher(): void
    {
        $keys = $this->context->getApplicationKeys(!$this->context->isClient());
        $cipherSuite = $this->context->getNegotiatedCipherSuite();
        $this->applicationReadCipher = $this->context->getCryptoFactory()
            ->createAead($keys['key'], $keys['iv'], $cipherSuite);
    }

    private function createAAD(ContentType $contentType, int $length): string
    {
        $version = $this->context->getNegotiatedVersion();
        if ($version == Version::TLS_1_3) {
            $version = Version::TLS_1_2;
        }
        return pack('Cnn', $contentType->value, $version->value, $length);
    }
}
