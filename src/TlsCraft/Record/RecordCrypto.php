<?php

namespace Php\TlsCraft\Record;

use Php\TlsCraft\Context;
use Php\TlsCraft\Crypto\Aead;
use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Logger;
use Php\TlsCraft\Protocol\ContentType;
use Php\TlsCraft\Protocol\Version;

class RecordCrypto
{
    private Context $context;

    // Early data phase ciphers (0-RTT)
    private ?Aead $earlyWriteCipher = null;
    private ?Aead $earlyReadCipher = null;
    private int $earlyWriteSequence = 0;
    private int $earlyReadSequence = 0;
    private bool $earlyKeysActive = false;

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

    // === Early Data Key Management ===

    /**
     * Activate early traffic keys for 0-RTT data
     * Called after deriving client_early_traffic_secret
     */
    public function activateEarlyKeys(): void
    {
        $this->earlyWriteCipher = null;  // Will be initialized on first use
        $this->earlyReadCipher = null;
        $this->earlyWriteSequence = 0;
        $this->earlyReadSequence = 0;
        $this->earlyKeysActive = true;

        Logger::debug('Early traffic keys activated');
    }

    /**
     * Deactivate early keys and switch to handshake keys
     * Called after sending/receiving EndOfEarlyData
     */
    public function deactivateEarlyKeys(): void
    {
        $this->earlyKeysActive = false;
        $this->earlyWriteCipher = null;
        $this->earlyReadCipher = null;

        Logger::debug('Early traffic keys deactivated, switching to handshake keys');
    }

    /**
     * Check if early keys are currently active
     */
    public function hasEarlyKeysActive(): bool
    {
        return $this->earlyKeysActive;
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

        // Use early keys if active (for 0-RTT data and EndOfEarlyData)
        if ($this->earlyKeysActive) {
            return $this->encryptWithEarlyKeys($record);
        }

        // Determine which cipher to use based on handshake completion
        if ($this->context->canDeriveApplicationSecrets()) {
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

        // Any outer Alert (0x15) is plaintext in TLS 1.3. Encrypted alerts would have outer type APPLICATION_DATA.
        if ($record->contentType === ContentType::ALERT) {
            return $record;
        }

        // Don't decrypt plaintext handshake records (before encryption starts)
        if ($record->contentType === ContentType::HANDSHAKE && !$this->hasHandshakeKeys() && !$this->earlyKeysActive) {
            return $record;
        }

        $keySchedule = $this->context->getKeySchedule();
        if (!$keySchedule) {
            return $record; // Return as-is during early handshake
        }

        // Server receiving early data uses early keys
        if ($this->earlyKeysActive && !$this->context->isClient()) {
            return $this->decryptWithEarlyKeys($record);
        }

        // Determine which cipher to use based on handshake completion
        if ($this->context->isHandshakeComplete() && $this->context->canDeriveApplicationSecrets()) {
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
        if (!$this->context->canDeriveApplicationSecrets()) {
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

    // === Early Data Encryption/Decryption ===

    private function encryptWithEarlyKeys(Record $record): Record
    {
        if (!$this->earlyWriteCipher) {
            $this->initializeEarlyWriteCipher();
        }

        $innerPlaintext = $record->payload.chr($record->contentType->value);
        $additionalData = $this->createAAD(ContentType::APPLICATION_DATA, strlen($innerPlaintext) + 16);

        $ciphertext = $this->earlyWriteCipher->encrypt(
            $innerPlaintext,
            $additionalData,
            $this->earlyWriteSequence++,
        );

        Logger::debug('Encrypt record with early keys (0-RTT)', [
            'Ciphertext length' => strlen($ciphertext),
            'Plaintext length' => strlen($innerPlaintext),
            'Seq' => $this->earlyWriteSequence - 1,
        ]);

        return new Record(
            ContentType::APPLICATION_DATA,
            $record->version,
            $ciphertext,
        );
    }

    private function decryptWithEarlyKeys(Record $record): Record
    {
        if (!$this->earlyReadCipher) {
            $this->initializeEarlyReadCipher();
        }

        $additionalData = $this->createAAD($record->contentType, strlen($record->payload));

        $plaintext = $this->earlyReadCipher->decrypt(
            $record->payload,
            $additionalData,
            $this->earlyReadSequence++,
        );

        Logger::debug('Decrypt record with early keys (0-RTT)', [
            'Ciphertext length' => strlen($record->payload),
            'Plaintext length' => strlen($plaintext),
            'Seq' => $this->earlyReadSequence - 1,
        ]);

        return $this->extractInnerRecord($plaintext, $record->version);
    }

    private function initializeEarlyWriteCipher(): void
    {
        $earlyTrafficSecret = $this->context->getClientEarlyTrafficSecret();
        if (!$earlyTrafficSecret) {
            throw new CraftException('Cannot initialize early write cipher: early traffic secret not derived');
        }

        $keySchedule = $this->context->getKeySchedule();
        $keys = $keySchedule->deriveTrafficKeys($earlyTrafficSecret);
        $cipherSuite = $this->context->getNegotiatedCipherSuite();

        $this->earlyWriteCipher = $this->context->getCryptoFactory()
            ->createAead($keys['key'], $keys['iv'], $cipherSuite);

        Logger::debug('Initialized early write cipher');
    }

    private function initializeEarlyReadCipher(): void
    {
        // Server uses client's early traffic secret for reading
        $earlyTrafficSecret = $this->context->getClientEarlyTrafficSecret();
        if (!$earlyTrafficSecret) {
            throw new CraftException('Cannot initialize early read cipher: early traffic secret not derived');
        }

        $keySchedule = $this->context->getKeySchedule();
        $keys = $keySchedule->deriveTrafficKeys($earlyTrafficSecret);
        $cipherSuite = $this->context->getNegotiatedCipherSuite();

        $this->earlyReadCipher = $this->context->getCryptoFactory()
            ->createAead($keys['key'], $keys['iv'], $cipherSuite);

        Logger::debug('Initialized early read cipher');
    }

    // === Existing Handshake/Application Encryption ===

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

        Logger::debug('Encrypt record with handshake keys', [
            'Ciphertext length' => strlen($ciphertext),
            'Ciphertext' => $ciphertext,
            'Plaintext length' => strlen($innerPlaintext),
            'Plaintext' => $innerPlaintext,
            'Additional data length' => strlen($additionalData),
            'Additional data' => $additionalData,
            'Seq' => $this->handshakeWriteSequence,
        ]);

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

        Logger::debug('Encrypt record with application keys', [
            'Ciphertext length' => strlen($ciphertext),
            'Ciphertext' => $ciphertext,
            'Plaintext length' => strlen($innerPlaintext),
            'Plaintext' => $innerPlaintext,
            'Additional data length' => strlen($additionalData),
            'Additional data' => $additionalData,
            'Seq' => $this->applicationWriteSequence,
        ]);

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

        Logger::debug('Decrypt record with handshake keys', [
            'Ciphertext length' => strlen($record->payload),
            'Ciphertext' => $record->payload,
            'Plaintext length' => strlen($plaintext),
            'Plaintext' => $plaintext,
            'Additional data length' => strlen($additionalData),
            'Additional data' => $additionalData,
            'Seq' => $this->handshakeReadSequence,
        ]);

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

        Logger::debug('Decrypt record with application keys', [
            'Ciphertext length' => strlen($record->payload),
            'Ciphertext' => $record->payload,
            'Plaintext length' => strlen($plaintext),
            'Plaintext' => $plaintext,
            'Additional data length' => strlen($additionalData),
            'Additional data' => $additionalData,
            'Seq' => $this->applicationReadSequence,
        ]);

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

        return $keySchedule && $keySchedule->hasHandshakeKeys();
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
