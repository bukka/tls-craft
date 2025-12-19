<?php

namespace Php\TlsCraft\Handshake\ExtensionParsers;

use Php\TlsCraft\Handshake\Extensions\PreSharedKeyExtension;
use Php\TlsCraft\Session\PskIdentity;

class PreSharedKeyExtensionParser
{
    public function parse(string $data, bool $isClientHello): PreSharedKeyExtension
    {
        $offset = 0;

        if ($isClientHello) {
            return $this->parseClientExtension($data, $offset);
        }

        return $this->parseServerExtension($data, $offset);
    }

    /**
     * Parse client extension (identities + binders)
     */
    private function parseClientExtension(string $data, int &$offset): PreSharedKeyExtension
    {
        // Parse identities
        $identitiesLength = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;

        $identities = [];
        $identitiesEnd = $offset + $identitiesLength;

        while ($offset < $identitiesEnd) {
            // Identity length
            $identityLength = unpack('n', substr($data, $offset, 2))[1];
            $offset += 2;

            // Identity
            $identity = substr($data, $offset, $identityLength);
            $offset += $identityLength;

            // Obfuscated ticket age
            $obfuscatedTicketAge = unpack('N', substr($data, $offset, 4))[1];
            $offset += 4;

            $identities[] = new PskIdentity($identity, $obfuscatedTicketAge);
        }

        // Parse binders
        $bindersLength = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;

        $binders = [];
        $bindersEnd = $offset + $bindersLength;

        while ($offset < $bindersEnd) {
            // Binder length
            $binderLength = unpack('C', substr($data, $offset, 1))[1];
            ++$offset;

            // Binder
            $binder = substr($data, $offset, $binderLength);
            $offset += $binderLength;

            $binders[] = $binder;
        }

        return PreSharedKeyExtension::forClientWithBinders($identities, $binders);
    }

    /**
     * Parse server extension (selected identity)
     */
    private function parseServerExtension(string $data, int &$offset): PreSharedKeyExtension
    {
        $selectedIdentity = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;

        return PreSharedKeyExtension::forServer($selectedIdentity);
    }
}
