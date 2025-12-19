<?php

namespace Php\TlsCraft\Handshake\ExtensionProviders;

use Php\TlsCraft\Context;
use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Handshake\Extensions\PreSharedKeyExtension;
use Php\TlsCraft\Handshake\ExtensionType;
use Php\TlsCraft\Logger;
use Php\TlsCraft\Session\PreSharedKey;
use Php\TlsCraft\Session\PskIdentity;

/**
 * Provider for PreSharedKey extension
 *
 * Note: This provider creates the extension WITHOUT binders.
 * Binders must be calculated separately after the full ClientHello
 * (minus binders) is serialized.
 */
class PreSharedKeyExtensionProvider implements ExtensionProvider
{
    public function create(Context $context): ?PreSharedKeyExtension
    {
        // First, check for manually configured external PSKs
        $offeredPsks = $context->getOfferedPsks();

        // If no external PSKs, try to load session tickets from storage
        if (empty($offeredPsks)) {
            $offeredPsks = $this->loadSessionTicketsFromStorage($context);

            if (!empty($offeredPsks)) {
                // Set loaded PSKs in context for later use (binder calculation)
                $context->setOfferedPsks($offeredPsks);

                Logger::debug('Loaded session tickets from storage', [
                    'count' => count($offeredPsks),
                    'server_name' => $context->getConfig()->getServerName(),
                ]);
            }
        }

        if (empty($offeredPsks)) {
            // No PSKs available (neither external nor from storage)
            Logger::debug('No PSKs available - skipping pre_shared_key extension');

            return null;
        }

        // Build identity array from PSKs
        $identities = [];
        foreach ($offeredPsks as $psk) {
            if ($psk->isResumption()) {
                // Session ticket resumption - calculate obfuscated ticket age
                $identities[] = PskIdentity::fromTicket(
                    $psk->identity,
                    $psk->getTicketAgeAdd(),
                    $psk->getTicketTimestamp(),
                );
            } else {
                // External PSK - no ticket age
                $identities[] = PskIdentity::external($psk->identity);
            }
        }

        Logger::debug('Creating pre_shared_key extension', [
            'identity_count' => count($identities),
            'psk_types' => array_map(fn ($psk) => $psk->isResumption() ? 'resumption' : 'external', $offeredPsks),
        ]);

        // Return extension without binders
        // Binders will be calculated and added during ClientHello serialization
        return PreSharedKeyExtension::forClient($identities);
    }

    /**
     * Load session tickets from storage and convert to PreSharedKey objects
     *
     * @return PreSharedKey[]
     */
    private function loadSessionTicketsFromStorage(Context $context): array
    {
        $config = $context->getConfig();

        // Check if session resumption is enabled and storage is configured
        if (!$config->isSessionResumptionEnabled() || !$config->hasSessionStorage()) {
            return [];
        }

        $storage = $config->getSessionStorage();
        $serverName = $config->getServerName();

        if (!$serverName) {
            Logger::debug('Cannot load session tickets: no server name configured');

            return [];
        }

        // Retrieve all valid tickets for this server
        $tickets = $storage->retrieveAll($serverName);

        if (empty($tickets)) {
            Logger::debug('No session tickets found in storage', [
                'server_name' => $serverName,
            ]);

            return [];
        }

        // Convert SessionTicket objects to PreSharedKey objects
        $psks = [];
        foreach ($tickets as $ticket) {
            // Skip invalid tickets (missing resumption secret or cipher suite)
            if (!$ticket->isValid()) {
                Logger::debug('Skipping invalid ticket', [
                    'is_opaque' => $ticket->isOpaque(),
                    'has_resumption_secret' => $ticket->resumptionSecret !== null,
                    'has_cipher_suite' => $ticket->cipherSuite !== null,
                ]);
                continue;
            }

            // Create PSK from ticket (works for both opaque and decrypted tickets)
            try {
                $psk = PreSharedKey::fromSessionTicket($ticket);
                $psks[] = $psk;

                $ticketAge = $ticket->getTicketAge();
                $obfuscatedAge = ($ticketAge + $ticket->ageAdd) & 0xFFFFFFFF;

                Logger::debug('Loaded session ticket for resumption', [
                    'server_name' => $serverName,
                    'is_opaque' => $ticket->isOpaque(),
                    'ticket_age_ms' => $ticketAge,
                    'obfuscated_age' => $obfuscatedAge,
                    'cipher_suite' => $ticket->getCipherSuite()->name,
                    'ticket_id' => substr($ticket->getIdentifier(), 0, 16).'...',
                ]);
            } catch (CraftException $e) {
                Logger::debug('Failed to create PSK from ticket', [
                    'error' => $e->getMessage(),
                ]);
                continue;
            }
        }

        return $psks;
    }

    public function getExtensionType(): ExtensionType
    {
        return ExtensionType::PRE_SHARED_KEY;
    }
}
