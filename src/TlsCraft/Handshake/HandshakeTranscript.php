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
    private function getMessagesData(array $messages): string
    {
        $result = '';
        foreach ($messages as $message) {
            $result .= $message['data'];
        }

        return $result;
    }

    /**
     * Get all message types as a comma-separated string
     */
    private function getMessagesTypes(array $messages): string
    {
        $types = [];
        foreach ($messages as $message) {
            $types[] = $message['type']->name;
        }

        return implode(',', $types);
    }

    /**
     * Get all messages as concatenated wire format
     */
    public function getAll(): string
    {
        return $this->getMessagesData($this->messages);
    }

    /**
     * Get all message types as a comma-separated string
     */
    public function getAllTypes(): string
    {
        return $this->getMessagesTypes($this->messages);
    }

    /**
     * Get all messages except the last N messages
     *
     * @param int $excludeCount Number of messages to exclude from the end
     *
     * @return string Concatenated wire format
     */
    public function getAllExceptLast(int $excludeCount = 1): string
    {
        if ($excludeCount <= 0) {
            return $this->getAll();
        }

        $count = count($this->messages);
        if ($excludeCount >= $count) {
            return ''; // Would exclude everything
        }

        $messages = array_slice($this->messages, 0, $count - $excludeCount);

        return $this->getMessagesData($messages);
    }

    /**
     * Get types of all messages except the last N messages
     *
     * @param int $excludeCount Number of messages to exclude from the end
     *
     * @return string Comma-separated message types
     */
    public function getAllTypesExceptLast(int $excludeCount = 1): string
    {
        if ($excludeCount <= 0) {
            return $this->getAllTypes();
        }

        $count = count($this->messages);
        if ($excludeCount >= $count) {
            return '';
        }

        $messages = array_slice($this->messages, 0, $count - $excludeCount);

        return $this->getMessagesTypes($messages);
    }

    /**
     * Get messages through (and including) a specific message type
     *
     * @return array<array{type: HandshakeType, data: string}>
     */
    private function getMessagesThrough(HandshakeType $throughType): array
    {
        $messages = [];

        foreach ($this->messages as $message) {
            $messages[] = $message;

            // Stop after including this type
            if ($message['type'] === $throughType) {
                break;
            }
        }

        return $messages;
    }

    /**
     * Get messages through (and including) a specific message type
     *
     * @param HandshakeType $throughType The last type to include
     *
     * @return string Concatenated wire format of all messages through the specified type
     */
    public function getThrough(HandshakeType $throughType): string
    {
        return $this->getMessagesData($this->getMessagesThrough($throughType));
    }

    /**
     * Get types through (and including) a specific message type
     *
     * @param HandshakeType $throughType The last type to include
     *
     * @return string Concatenated types
     */
    public function getTypesThrough(HandshakeType $throughType): string
    {
        return $this->getMessagesTypes($this->getMessagesThrough($throughType));
    }

    /**
     * Get last message data
     */
    public function getLast(): string
    {
        return $this->messages[count($this->messages) - 1]['data'];
    }

    /**
     * Get transcript hash over all messages
     */
    public function getHash(string $hashAlgorithm): string
    {
        return hash($hashAlgorithm, $this->getAll(), true);
    }

    /**
     * Get transcript hash over all messages
     */
    public function getHashAllExceptLast(string $hashAlgorithm, int $excludeCount = 1): string
    {
        return hash($hashAlgorithm, $this->getAllExceptLast($excludeCount), true);
    }

    /**
     * Get transcript hash through (and including) a specific message type
     */
    public function getHashThrough(string $hashAlgorithm, HandshakeType $throughType): string
    {
        return hash($hashAlgorithm, $this->getThrough($throughType), true);
    }

    /**
     * Get count of messages
     */
    public function count(): int
    {
        return count($this->messages);
    }
}
