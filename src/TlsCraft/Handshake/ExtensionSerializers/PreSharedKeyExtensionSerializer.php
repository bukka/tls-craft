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
            $identitiesData .= pack('n', $identity->getLength());
            $identitiesData .= $identity->identity;
            $identitiesData .= pack('N', $identity->obfuscatedTicketAge);
        }

        // Binders (use actual binders or zeros if not set)
        $bindersData = '';
        $binderCount = count($extension->identities);

        if ($extension->hasBinders()) {
            // Use actual binders
            foreach ($extension->binders as $binder) {
                $bindersData .= pack('C', strlen($binder));
                $bindersData .= $binder;
            }
        } else {
            // Use placeholder zeros (for first pass calculation)
            // Binder length depends on the hash algorithm of the cipher suite
            // For now, use 32 bytes (SHA256) as default
            $binderLength = $this->getBinderLength();
            for ($i = 0; $i < $binderCount; ++$i) {
                $bindersData .= pack('C', $binderLength);
                $bindersData .= str_repeat("\x00", $binderLength);
            }
        }

        // Combine
        $data = pack('n', strlen($identitiesData)).$identitiesData;
        $data .= pack('n', strlen($bindersData)).$bindersData;

        return $data;
    }

    /**
     * Serialize server extension (selected identity index)
     */
    private function serializeServerExtension(PreSharedKeyExtension $extension): string
    {
        return pack('n', $extension->selectedIdentity);
    }

    /**
     * Serialize only identities portion (without binders section)
     * Used for binder calculation
     */
    public function serializeIdentitiesOnly(PreSharedKeyExtension $extension): string
    {
        $identitiesData = '';
        foreach ($extension->identities as $identity) {
            $identitiesData .= pack('n', $identity->getLength());
            $identitiesData .= $identity->identity;
            $identitiesData .= pack('N', $identity->obfuscatedTicketAge);
        }

        return pack('n', strlen($identitiesData)).$identitiesData;
    }

    /**
     * Get binder length based on cipher suite hash algorithm
     */
    private function getBinderLength(): int
    {
        // Get from context's negotiated cipher suite or offered PSKs
        $offeredPsks = $this->context->getOfferedPsks();

        if (!empty($offeredPsks)) {
            // Use first PSK's cipher suite to determine hash length
            return $offeredPsks[0]->cipherSuite->getHashLength();
        }

        // Default to SHA256 (32 bytes)
        return 32;
    }
}
