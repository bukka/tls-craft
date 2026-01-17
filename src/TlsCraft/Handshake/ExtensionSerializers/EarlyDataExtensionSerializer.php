<?php

namespace Php\TlsCraft\Handshake\ExtensionSerializers;

use Php\TlsCraft\Handshake\Extensions\EarlyDataExtension;

/**
 * Serializer for EarlyData extension
 *
 * Format varies by context:
 * - ClientHello: Empty (0 bytes)
 * - EncryptedExtensions: Empty (0 bytes)
 * - NewSessionTicket: uint32 max_early_data_size
 */
class EarlyDataExtensionSerializer extends AbstractExtensionSerializer
{
    public function serialize(EarlyDataExtension $extension): string
    {
        // NewSessionTicket context - contains max_early_data_size
        if ($extension->hasMaxEarlyDataSize()) {
            return pack('N', $extension->maxEarlyDataSize);
        }

        // ClientHello or EncryptedExtensions - empty
        return '';
    }
}
