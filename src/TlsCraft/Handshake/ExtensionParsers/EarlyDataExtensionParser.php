<?php

namespace Php\TlsCraft\Handshake\ExtensionParsers;

use Php\TlsCraft\Handshake\Extensions\EarlyDataExtension;
use Php\TlsCraft\Logger;

/**
 * Parser for EarlyData extension
 *
 * Parses:
 * - Empty extension in EncryptedExtensions (server accepted early data)
 * - uint32 max_early_data_size in NewSessionTicket
 */
class EarlyDataExtensionParser extends AbstractExtensionParser
{
    /**
     * Parse early_data extension
     *
     * @param string $data     Extension data (may be empty)
     * @param bool   $isTicket True if parsing from NewSessionTicket context
     */
    public function parse(string $data, bool $isTicket = false): EarlyDataExtension
    {
        // Empty extension (ClientHello or EncryptedExtensions)
        if ($data === '') {
            Logger::debug('EarlyData: Parsed empty extension (acceptance indicator)');

            return EarlyDataExtension::forEncryptedExtensions();
        }

        // NewSessionTicket context - contains max_early_data_size
        if (strlen($data) === 4) {
            $maxEarlyDataSize = unpack('N', $data)[1];

            Logger::debug('EarlyData: Parsed from NewSessionTicket', [
                'max_early_data_size' => $maxEarlyDataSize,
            ]);

            return EarlyDataExtension::forNewSessionTicket($maxEarlyDataSize);
        }

        // Unexpected length
        Logger::debug('EarlyData: Unexpected extension length', [
            'length' => strlen($data),
        ]);

        // Treat as empty (accepted)
        return EarlyDataExtension::forEncryptedExtensions();
    }
}
