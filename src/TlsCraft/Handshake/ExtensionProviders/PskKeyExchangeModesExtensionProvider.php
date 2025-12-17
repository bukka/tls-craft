<?php

namespace Php\TlsCraft\Handshake\ExtensionProviders;

use Php\TlsCraft\Context;
use Php\TlsCraft\Handshake\Extensions\PskKeyExchangeModesExtension;
use Php\TlsCraft\Handshake\ExtensionType;

/**
 * Provider for PskKeyExchangeModes extension
 */
class PskKeyExchangeModesExtensionProvider implements ExtensionProvider
{
    /**
     * @param int[] $modes
     */
    public function __construct(
        private readonly array $modes = [PskKeyExchangeModesExtension::PSK_DHE_KE],
    ) {
    }

    /**
     * Create provider with default mode (PSK with DHE)
     */
    public static function default(): self
    {
        return new self();
    }

    /**
     * Create provider supporting both modes
     */
    public static function both(): self
    {
        return new self([
            PskKeyExchangeModesExtension::PSK_KE,
            PskKeyExchangeModesExtension::PSK_DHE_KE,
        ]);
    }

    public function create(Context $context): ?PskKeyExchangeModesExtension
    {
        if (empty($this->modes)) {
            return null;
        }

        return new PskKeyExchangeModesExtension($this->modes);
    }

    public function getExtensionType(): ExtensionType
    {
        return ExtensionType::PSK_KEY_EXCHANGE_MODES;
    }
}
