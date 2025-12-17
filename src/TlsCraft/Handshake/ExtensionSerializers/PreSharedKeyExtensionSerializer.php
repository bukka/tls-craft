<?php

namespace Php\TlsCraft\Handshake\ExtensionSerializers;

use Php\TlsCraft\Handshake\Extensions\PreSharedKeyExtension;

/**
 * Serializer for PreSharedKey extension
 */
class PreSharedKeyExtensionSerializer extends AbstractExtensionSerializer
{
    public function serialize(PreSharedKeyExtension $extension): string
    {
        if ($extension->isServerExtension()) {
            return $this->serializeServerExtension($extension);
        }

        return $this->serializeClientExtension($extension);
    }

    /**
     * Serialize client extension (identities + binders)
     */
    private function serializeClientExtension(PreSharedKeyExtension $extension): string
    {
        // Identities
        $identitiesData = '';
        foreach ($extension->identities as $identity) {
            // identity length (2 bytes) + identity + obfuscated_ticket_age (4 bytes)
            $identitiesData .= pack('n', $identity->getLength());
            $identitiesData .= $identity->identity;
            $identitiesData .= pack('N', $identity->obfuscatedTicketAge);
        }

        // Binders
        $bindersData = '';
        foreach ($extension->binders as $binder) {
            // binder length (1 byte) + binder
            $bindersData .= pack('C', strlen($binder));
            $bindersData .= $binder;
        }

        // Combine: identities_length (2 bytes) + identities + binders_length (2 bytes) + binders
        $data = pack('n', strlen($identitiesData)).$identitiesData;
        $data .= pack('n', strlen($bindersData)).$bindersData;

        return $data;
    }

    /**
     * Serialize server extension (selected identity index)
     */
    private function serializeServerExtension(PreSharedKeyExtension $extension): string
    {
        // Just the selected identity index (2 bytes)
        return pack('n', $extension->selectedIdentity);
    }

    /**
     * Serialize without binders (for binder calculation)
     * Returns serialized identities portion only
     */
    public function serializeWithoutBinders(PreSharedKeyExtension $extension): string
    {
        $identitiesData = '';
        foreach ($extension->identities as $identity) {
            $identitiesData .= pack('n', $identity->getLength());
            $identitiesData .= $identity->identity;
            $identitiesData .= pack('N', $identity->obfuscatedTicketAge);
        }

        return pack('n', strlen($identitiesData)).$identitiesData;
    }
}
