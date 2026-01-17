<?php

namespace Php\TlsCraft\Handshake\ExtensionProviders;

use Php\TlsCraft\Context;
use Php\TlsCraft\Handshake\Extensions\EarlyDataExtension;
use Php\TlsCraft\Handshake\ExtensionType;
use Php\TlsCraft\Logger;

/**
 * Provider for EarlyData extension
 *
 * For ClientHello: Creates extension only when:
 * 1. Client has early data to send
 * 2. A PSK is available with max_early_data_size > 0
 * 3. Early data is enabled in config
 *
 * For EncryptedExtensions (server): Creates extension when server accepts early data
 *
 * For NewSessionTicket: Creates extension with max_early_data_size
 */
class EarlyDataExtensionProvider implements ExtensionProvider
{
    public function __construct(
        private readonly ?int $maxEarlyDataSize = null,
    ) {
    }

    /**
     * Create provider for ClientHello (empty extension)
     */
    public static function forClientHello(): self
    {
        return new self(null);
    }

    /**
     * Create provider for NewSessionTicket with max size
     */
    public static function forNewSessionTicket(int $maxEarlyDataSize): self
    {
        return new self($maxEarlyDataSize);
    }

    public function create(Context $context): ?EarlyDataExtension
    {
        $config = $context->getConfig();

        // For NewSessionTicket context (server creating ticket)
        if ($this->maxEarlyDataSize !== null) {
            return EarlyDataExtension::forNewSessionTicket($this->maxEarlyDataSize);
        }

        // For ClientHello context
        if ($context->isClient()) {
            return $this->createForClientHello($context);
        }

        // For EncryptedExtensions context (server accepting early data)
        return $this->createForEncryptedExtensions($context);
    }

    private function createForClientHello(Context $context): ?EarlyDataExtension
    {
        $config = $context->getConfig();

        // Check if early data is enabled
        if (!$config->isEarlyDataEnabled()) {
            Logger::debug('EarlyData: Not enabled in config');

            return null;
        }

        // Check if we have early data to send
        if (!$config->hasEarlyData()) {
            Logger::debug('EarlyData: No early data configured');

            return null;
        }

        // Check if we have a PSK that supports early data
        $psks = $context->getOfferedPsks();
        if (empty($psks)) {
            Logger::debug('EarlyData: No PSKs available');

            return null;
        }

        // Check if first PSK (the one we'll use) supports early data
        $firstPsk = $psks[0];
        $ticket = $context->getSessionTickets()[0] ?? null;

        if ($ticket === null) {
            Logger::debug('EarlyData: No session ticket available');

            return null;
        }

        $maxSize = $ticket->getMaxEarlyDataSize();
        if ($maxSize <= 0) {
            Logger::debug('EarlyData: Ticket does not support early data', [
                'max_early_data_size' => $maxSize,
            ]);

            return null;
        }

        // Check if our early data fits
        $earlyData = $config->getEarlyData();
        if (strlen($earlyData) > $maxSize) {
            Logger::debug('EarlyData: Data exceeds max size', [
                'data_size' => strlen($earlyData),
                'max_size' => $maxSize,
            ]);

            return null;
        }

        Logger::debug('EarlyData: Creating extension for ClientHello', [
            'data_size' => strlen($earlyData),
            'max_size' => $maxSize,
        ]);

        // Mark that we're attempting early data
        $context->setEarlyDataAttempted(true);

        return EarlyDataExtension::forClientHello();
    }

    private function createForEncryptedExtensions(Context $context): ?EarlyDataExtension
    {
        // Server should only include this if it accepted early data
        if (!$context->isEarlyDataAccepted()) {
            return null;
        }

        Logger::debug('EarlyData: Creating extension for EncryptedExtensions (server accepted)');

        return EarlyDataExtension::forEncryptedExtensions();
    }

    public function getExtensionType(): ExtensionType
    {
        return ExtensionType::EARLY_DATA;
    }
}
