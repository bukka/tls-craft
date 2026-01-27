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
        // For ClientHello context
        if ($context->isClient()) {
            return $this->createForClientHello($context);
        }

        // Server-side contexts: EncryptedExtensions or NewSessionTicket
        // We need to distinguish between them

        // For EncryptedExtensions: check if server accepted early data
        // This is called during handshake when isHandshakeComplete() is false
        if (!$context->isHandshakeComplete()) {
            return $this->createForEncryptedExtensions($context);
        }

        // For NewSessionTicket context (post-handshake)
        // Only include if maxEarlyDataSize is configured
        if ($this->maxEarlyDataSize !== null && $this->maxEarlyDataSize > 0) {
            return EarlyDataExtension::forNewSessionTicket($this->maxEarlyDataSize);
        }

        return null;
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

        // Check if we have session tickets OR external PSKs
        $tickets = $context->getSessionTickets();
        $externalPsks = $config->getExternalPsks();

        if (empty($tickets) && empty($externalPsks)) {
            Logger::debug('EarlyData: No session tickets or external PSKs available');

            return null;
        }

        // Get max_early_data_size from available sources
        $maxSize = 0;

        // Try session ticket first
        if (!empty($tickets)) {
            $maxSize = $tickets[0]->getMaxEarlyDataSize();
            Logger::debug('EarlyData: Checking session ticket', [
                'max_size' => $maxSize,
            ]);
        }

        // Fall back to external PSK
        if ($maxSize <= 0 && !empty($externalPsks)) {
            $maxSize = $externalPsks[0]->maxEarlyDataSize;
            Logger::debug('EarlyData: Using external PSK', [
                'max_size' => $maxSize,
            ]);
        }

        // Fall back to Config
        if ($maxSize <= 0) {
            $maxSize = $config->getMaxEarlyDataSize();
            if ($maxSize > 0) {
                Logger::debug('EarlyData: Using Config max_early_data_size', [
                    'max_size' => $maxSize,
                ]);
            }
        }

        // Check if our early data exceeds the limit (only if a limit is set)
        $earlyData = $config->getEarlyData();
        if ($maxSize > 0 && strlen($earlyData) > $maxSize) {
            Logger::debug('EarlyData: Data exceeds max size', [
                'data_size' => strlen($earlyData),
                'max_size' => $maxSize,
            ]);

            return null;
        }

        Logger::debug('EarlyData: Creating extension for ClientHello', [
            'data_size' => strlen($earlyData),
            'max_size' => $maxSize > 0 ? $maxSize : 'unlimited',
            'has_tickets' => !empty($tickets),
            'has_external_psks' => !empty($externalPsks),
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
