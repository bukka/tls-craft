<?php

namespace Php\TlsCraft\Session;

use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Logger;

use const OPENSSL_RAW_DATA;

/**
 * Encrypted session ticket serializer using AES-256-GCM
 * Provides confidentiality and authenticity for session tickets
 */
class EncryptedSessionTicketSerializer extends AbstractSessionTicketSerializer
{
    private const CIPHER = 'aes-256-gcm';
    private const IV_LENGTH = 12;
    private const TAG_LENGTH = 16;

    public function __construct(
        private readonly string $encryptionKey,
    ) {
        if (strlen($encryptionKey) !== 32) {
            throw new CraftException('Encryption key must be 32 bytes for AES-256');
        }
    }

    public function serialize(SessionTicketData $data): string
    {
        // Convert to JSON using parent method
        $json = $this->encodeToJson($data);

        // Generate random IV
        $iv = random_bytes(self::IV_LENGTH);

        // Encrypt with AEAD
        $tag = '';
        $ciphertext = openssl_encrypt(
            $json,
            self::CIPHER,
            $this->encryptionKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            self::TAG_LENGTH,
        );

        if ($ciphertext === false) {
            throw new CraftException('Failed to encrypt ticket');
        }

        Logger::debug('Encrypted session ticket', [
            'iv_length' => strlen($iv),
            'tag_length' => strlen($tag),
            'ciphertext_length' => strlen($ciphertext),
            'total_length' => strlen($iv) + strlen($tag) + strlen($ciphertext),
        ]);

        // Format: IV || TAG || Ciphertext
        return $iv.$tag.$ciphertext;
    }

    public function unserialize(string $ticket): ?SessionTicketData
    {
        $minLength = self::IV_LENGTH + self::TAG_LENGTH;
        if (strlen($ticket) < $minLength) {
            Logger::debug('Ticket too short to decrypt', [
                'length' => strlen($ticket),
                'required_min' => $minLength,
            ]);

            return null;
        }

        // Extract components
        $iv = substr($ticket, 0, self::IV_LENGTH);
        $tag = substr($ticket, self::IV_LENGTH, self::TAG_LENGTH);
        $ciphertext = substr($ticket, self::IV_LENGTH + self::TAG_LENGTH);

        Logger::debug('Decrypting session ticket', [
            'iv_length' => strlen($iv),
            'tag_length' => strlen($tag),
            'ciphertext_length' => strlen($ciphertext),
        ]);

        // Decrypt with AEAD
        $json = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $this->encryptionKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
        );

        if ($json === false) {
            Logger::debug('Failed to decrypt ticket (invalid or tampered)');

            return null;
        }

        // Decode JSON using parent method
        $ticketData = $this->decodeFromJson($json);

        if ($ticketData !== null) {
            Logger::debug('Successfully decrypted and parsed ticket', [
                'server_name' => $ticketData->serverName,
                'cipher_suite' => $ticketData->cipherSuite->name,
                'timestamp' => $ticketData->timestamp,
            ]);
        }

        return $ticketData;
    }
}
