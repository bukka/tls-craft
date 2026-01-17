<?php

namespace Php\TlsCraft\Protocol;

/**
 * Server-side early data handling modes (RFC 8446 Section 4.2.10)
 *
 * When a server receives a ClientHello with the early_data extension,
 * it has three options for how to respond.
 */
enum EarlyDataServerMode: string
{
    /**
     * Accept early data and process it.
     *
     * Server includes early_data extension in EncryptedExtensions,
     * decrypts and processes early data, waits for EndOfEarlyData.
     */
    case ACCEPT = 'accept';

    /**
     * Reject early data silently (ignore and skip).
     *
     * Server returns a regular 1-RTT response without early_data in
     * EncryptedExtensions. Server attempts to deprotect received records
     * using handshake traffic key, discarding records which fail
     * deprotection (up to max_early_data_size).
     *
     * This is the safest option when replay protection cannot be guaranteed.
     */
    case REJECT = 'reject';

    /**
     * Request client to retry without early data.
     *
     * Server sends HelloRetryRequest. Client MUST NOT include early_data
     * extension in its followup ClientHello. Server skips all records
     * with external content type "application_data" up to max_early_data_size.
     *
     * Useful when server needs to change cipher suite or key share.
     */
    case HELLO_RETRY_REQUEST = 'hello_retry_request';

    /**
     * Get human-readable description
     */
    public function getDescription(): string
    {
        return match ($this) {
            self::ACCEPT => 'Accept and process early data',
            self::REJECT => 'Reject early data silently (1-RTT fallback)',
            self::HELLO_RETRY_REQUEST => 'Send HelloRetryRequest to force retry without early data',
        };
    }

    /**
     * Check if this mode requires skipping early data records
     */
    public function requiresSkippingEarlyData(): bool
    {
        return match ($this) {
            self::ACCEPT => false,
            self::REJECT => true,
            self::HELLO_RETRY_REQUEST => true,
        };
    }

    /**
     * Check if early_data extension should be included in EncryptedExtensions
     */
    public function includesExtensionInEncryptedExtensions(): bool
    {
        return $this === self::ACCEPT;
    }
}
