<?php

namespace Php\TlsCraft\Session;

use Exception;
use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Logger;
use RuntimeException;

/**
 * Abstract base for session ticket serializers
 * Handles common JSON encoding/decoding logic
 */
abstract class AbstractSessionTicketSerializer implements SessionTicketSerializer
{
    /**
     * Encode ticket data to JSON
     */
    protected function encodeToJson(SessionTicketData $data): string
    {
        $array = [
            'version' => $data->version,
            'cipher_suite' => $data->cipherSuite->value,
            'timestamp' => $data->timestamp,
            'max_early_data' => $data->maxEarlyDataSize,
            'resumption_secret' => base64_encode($data->resumptionSecret),
            'nonce' => base64_encode($data->nonce),
            'server_name' => $data->serverName,
        ];

        $json = json_encode($array);

        if ($json === false) {
            throw new RuntimeException('Failed to encode ticket as JSON: '.json_last_error_msg());
        }

        return $json;
    }

    /**
     * Decode JSON to ticket data
     */
    protected function decodeFromJson(string $json): ?SessionTicketData
    {
        $array = json_decode($json, true);

        if (!is_array($array)) {
            Logger::debug('Failed to decode ticket JSON', [
                'error' => json_last_error_msg(),
            ]);

            return null;
        }

        // Validate required fields
        if (!isset(
            $array['resumption_secret'],
            $array['cipher_suite'],
            $array['timestamp'],
            $array['nonce'],
            $array['server_name'],
        )) {
            Logger::debug('Ticket missing required fields', [
                'fields' => array_keys($array),
            ]);

            return null;
        }

        try {
            $resumptionSecret = base64_decode($array['resumption_secret'], true);
            $nonce = base64_decode($array['nonce'], true);

            if ($resumptionSecret === false || $nonce === false) {
                Logger::debug('Failed to decode base64 fields');

                return null;
            }

            return new SessionTicketData(
                resumptionSecret: $resumptionSecret,
                cipherSuite: CipherSuite::from($array['cipher_suite']),
                timestamp: $array['timestamp'],
                nonce: $nonce,
                serverName: $array['server_name'],
                maxEarlyDataSize: $array['max_early_data'] ?? 0,
                version: $array['version'] ?? 1,
            );
        } catch (Exception $e) {
            Logger::debug('Failed to create SessionTicketData from ticket', [
                'error' => $e->getMessage(),
            ]);

            return null;
        }
    }
}
