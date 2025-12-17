<?php

namespace Php\TlsCraft\Handshake\Extensions;

use Php\TlsCraft\Handshake\ExtensionType;

/**
 * PSK Key Exchange Modes Extension (RFC 8446 Section 4.2.9)
 *
 * Indicates which PSK key exchange modes the client supports
 */
class PskKeyExchangeModesExtension extends Extension
{
    public const PSK_KE = 0;      // PSK-only key establishment
    public const PSK_DHE_KE = 1;  // PSK with (EC)DHE key establishment

    /**
     * @param int[] $modes - Array of supported modes
     */
    public function __construct(
        public readonly array $modes,
    ) {
        parent::__construct(ExtensionType::PSK_KEY_EXCHANGE_MODES);
    }

    /**
     * Create with default modes (PSK with DHE)
     */
    public static function default(): self
    {
        return new self([self::PSK_DHE_KE]);
    }

    /**
     * Create with PSK-only mode
     */
    public static function pskOnly(): self
    {
        return new self([self::PSK_KE]);
    }

    /**
     * Create with both modes
     */
    public static function both(): self
    {
        return new self([self::PSK_KE, self::PSK_DHE_KE]);
    }

    /**
     * Check if PSK-only mode is supported
     */
    public function supportsPskOnly(): bool
    {
        return in_array(self::PSK_KE, $this->modes, true);
    }

    /**
     * Check if PSK with DHE mode is supported
     */
    public function supportsPskDhe(): bool
    {
        return in_array(self::PSK_DHE_KE, $this->modes, true);
    }

    /**
     * Get mode name
     */
    public static function getModeName(int $mode): string
    {
        return match ($mode) {
            self::PSK_KE => 'psk_ke',
            self::PSK_DHE_KE => 'psk_dhe_ke',
            default => "unknown({$mode})",
        };
    }
}
