<?php

namespace Php\TlsCraft;

use Php\TlsCraft\Exceptions\CraftException;

use const OPENSSL_VERSION_NUMBER;
use const OPENSSL_VERSION_TEXT;

final class RuntimeEnvironment
{
    public static function assertOpenSsl3(): void
    {
        if (!extension_loaded('openssl')) {
            throw new CraftException('Required PHP extension not loaded: openssl');
        }

        // OPENSSL_VERSION_NUMBER: for OpenSSL 3.x it's >= 0x30000000
        if (defined('OPENSSL_VERSION_NUMBER') && OPENSSL_VERSION_NUMBER >= 0x30000000) {
            return;
        }

        // Fallback/extra safety using OPENSSL_VERSION_TEXT
        if (defined('OPENSSL_VERSION_TEXT')) {
            // e.g. "OpenSSL 3.0.12 1 Jun 2024"
            if (preg_match('/OpenSSL\s+(\d+)\./i', OPENSSL_VERSION_TEXT, $m) && (int) $m[1] >= 3) {
                return;
            }
            $found = OPENSSL_VERSION_TEXT;
        } else {
            $found = 'unknown';
        }

        throw new CraftException("OpenSSL 3.x is required for EC key exchange; found: {$found}");
    }
}
