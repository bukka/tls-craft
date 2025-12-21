<?php

namespace Php\TlsCraft\Session;

use Php\TlsCraft\Config;
use Php\TlsCraft\Logger;

/**
 * Resolves PSK identities to PreSharedKey instances (SERVER SIDE)
 * Priority: External PSKs → Stateless tickets → Stateful storage
 */
class PskResolver
{
    public function __construct(
        private readonly Config $config,
        private readonly ?SessionTicketSerializer $serializer = null,
    ) {
    }

    /**
     * Look up PSK by ticket identity
     *
     * @param string      $ticketIdentity The ticket bytes from client
     * @param string|null $serverName     The SNI server name from ClientHello (required for storage lookup)
     */
    public function resolve(string $ticketIdentity, ?string $serverName = null): ?PreSharedKey
    {
        // 1. Check external PSKs first (not bound to server name)
        $externalPsk = $this->lookupExternalPsk($ticketIdentity);
        if ($externalPsk !== null) {
            Logger::debug('PskResolver: Found external PSK');

            return $externalPsk;
        }

        // 2. Try stateless ticket deserialization
        if ($this->serializer !== null) {
            $statelessPsk = $this->deserializeTicket($ticketIdentity, $serverName);
            if ($statelessPsk !== null) {
                Logger::debug('PskResolver: Deserialized stateless ticket', [
                    'cipher_suite' => $statelessPsk->cipherSuite->name,
                ]);

                return $statelessPsk;
            }
        }

        // 3. Fall back to storage (requires server name)
        if ($serverName !== null) {
            $storage = $this->config->getSessionStorage();
            if ($storage !== null) {
                $storedPsk = $this->lookupStoredTicket($ticketIdentity, $serverName);
                if ($storedPsk !== null) {
                    Logger::debug('PskResolver: Found in storage', [
                        'server_name' => $serverName,
                        'cipher_suite' => $storedPsk->cipherSuite->name,
                    ]);

                    return $storedPsk;
                }
            }
        } else {
            Logger::debug('PskResolver: Cannot lookup stored ticket without server name');
        }

        Logger::debug('PskResolver: No PSK found');

        return null;
    }

    private function lookupExternalPsk(string $identity): ?PreSharedKey
    {
        foreach ($this->config->getExternalPsks() as $psk) {
            if ($psk->identity === $identity) {
                return $psk;
            }
        }

        return null;
    }

    private function deserializeTicket(string $ticketBytes, ?string $expectedServerName): ?PreSharedKey
    {
        $ticketData = $this->serializer->unserialize($ticketBytes);
        if ($ticketData === null) {
            return null;
        }

        // Validate ticket hasn't expired
        if ($ticketData->isExpired()) {
            Logger::debug('PskResolver: Stateless ticket expired');

            return null;
        }

        // SECURITY: Validate server name matches
        if ($expectedServerName !== null && $ticketData->serverName !== $expectedServerName) {
            Logger::error('PskResolver: Server name mismatch in ticket', [
                'expected' => $expectedServerName,
                'in_ticket' => $ticketData->serverName,
            ]);

            return null;
        }

        return new PreSharedKey(
            identity: $ticketBytes,
            secret: $ticketData->resumptionSecret,
            cipherSuite: $ticketData->cipherSuite,
            maxEarlyDataSize: $ticketData->maxEarlyDataSize,
        );
    }

    private function lookupStoredTicket(string $ticketIdentity, string $serverName): ?PreSharedKey
    {
        $storage = $this->config->getSessionStorage();
        if ($storage === null) {
            return null;
        }

        // Look up tickets for this specific server name only
        $tickets = $storage->retrieveAll($serverName);

        $ticketHash = hash('sha256', $ticketIdentity);

        foreach ($tickets as $ticket) {
            if ($ticket->getIdentifier() === $ticketHash) {
                if ($ticket->isExpired()) {
                    Logger::debug('PskResolver: Stored ticket expired');

                    return null;
                }

                return PreSharedKey::fromSessionTicket($ticket);
            }
        }

        return null;
    }
}
