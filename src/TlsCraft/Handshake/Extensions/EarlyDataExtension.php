<?php

namespace Php\TlsCraft\Handshake\Extensions;

use Php\TlsCraft\Handshake\ExtensionType;

/**
 * Early Data Extension (RFC 8446 Section 4.2.10)
 *
 * Used in:
 * - ClientHello: Empty, indicates client wants to send early data
 * - EncryptedExtensions: Empty, indicates server accepted early data
 * - NewSessionTicket: Contains max_early_data_size
 */
class EarlyDataExtension extends Extension
{
    /**
     * @param int|null $maxEarlyDataSize Only set in NewSessionTicket context
     */
    public function __construct(
        public readonly ?int $maxEarlyDataSize = null,
    ) {
        parent::__construct(ExtensionType::EARLY_DATA);
    }

    /**
     * Create empty extension for ClientHello
     */
    public static function forClientHello(): self
    {
        return new self(null);
    }

    /**
     * Create empty extension for EncryptedExtensions (server acceptance)
     */
    public static function forEncryptedExtensions(): self
    {
        return new self(null);
    }

    /**
     * Create extension for NewSessionTicket with max size
     */
    public static function forNewSessionTicket(int $maxEarlyDataSize): self
    {
        return new self($maxEarlyDataSize);
    }

    /**
     * Check if this is a NewSessionTicket context (has max size)
     */
    public function hasMaxEarlyDataSize(): bool
    {
        return $this->maxEarlyDataSize !== null;
    }

    /**
     * Check if early data is enabled (max size > 0)
     */
    public function isEarlyDataEnabled(): bool
    {
        return $this->maxEarlyDataSize !== null && $this->maxEarlyDataSize > 0;
    }
}
