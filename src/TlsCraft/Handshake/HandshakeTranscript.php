<?php

namespace Php\TlsCraft\Handshake;

use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Protocol\HandshakeType;

/**
 * Manages the handshake message transcript for TLS 1.3
 *
 * This class maintains an ordered list of handshake messages and provides
 * methods to compute transcript hashes over specific ranges, typically
 * identified by HandshakeType boundaries.
 */
class HandshakeTranscript
{
    /** @var array<array{type: HandshakeType, data: string}> */
    private array $messages = [];

    /**
     * Add a handshake message to the transcript
     * The type is extracted from the first byte of the wire format
     */
    public function addMessage(string $wireFormat): void
    {
        if (strlen($wireFormat) < 4) {
            throw new CraftException('Invalid handshake message: too short');
        }

        // First byte is the handshake type
        $type = HandshakeType::from(ord($wireFormat[0]));

        $this->messages[] = [
            'type' => $type,
            'data' => $wireFormat,
        ];
    }

    /**
     * Get all messages as concatenated wire format
     */
    public function getAll(): string
    {
        $result = '';
        foreach ($this->messages as $message) {
            $result .= $message['data'];
        }
        return $result;
    }

    /**
     * Get messages through (and including) a specific message type
     *
     * @param HandshakeType $throughType The last type to include
     * @return string Concatenated wire format of all messages through the specified type
     */
    public function getThrough(HandshakeType $throughType): string
    {
        $result = '';

        foreach ($this->messages as $message) {
            $result .= $message['data'];

            // Stop after including this type
            if ($message['type'] === $throughType) {
                break;
            }
        }

        return $result;
    }

    /**
     * Get transcript hash over all messages
     */
    public function getHash(string $hashAlgorithm): string
    {
        return hash($hashAlgorithm, $this->getAll(), true);
    }

    /**
     * Get transcript hash through (and including) a specific message type
     */
    public function getHashThrough(string $hashAlgorithm, HandshakeType $throughType): string
    {
        return hash($hashAlgorithm, $this->getThrough($throughType), true);
    }

    /**
     * Get the last message type, or null if no messages
     */
    public function getLastMessageType(): ?HandshakeType
    {
        if (empty($this->messages)) {
            return null;
        }

        return $this->messages[count($this->messages) - 1]['type'];
    }

    /**
     * Get count of messages
     */
    public function count(): int
    {
        return count($this->messages);
    }
}
