<?php

namespace Php\TlsCraft\Crypto;

use Php\TlsCraft\Exceptions\CryptoException;
use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Logger;

use const X509_PURPOSE_SSL_CLIENT;
use const X509_PURPOSE_SSL_SERVER;

class CertificateVerifier
{
    /**
     * Verify one certificate is signed by another
     */
    public function verifyCertificateSignature(Certificate $cert, Certificate $issuer): bool
    {
        $certResource = $cert->getResource();
        $issuerPublicKey = $issuer->getPublicKey();

        $result = openssl_x509_verify($certResource, $issuerPublicKey);

        Logger::debug('Certificate signature verification', [
            'Result' => $result === 1 ? 'valid' : 'invalid',
        ]);

        return $result === 1;
    }

    /**
     * Verify certificate against system CA bundle
     */
    public function verifyWithSystemCaBundle(Certificate $certificate, bool $isClient): void
    {
        Logger::debug('Verifying certificate with system CA bundle');

        $certResource = $certificate->getResource();
        $purpose = $isClient ? X509_PURPOSE_SSL_SERVER : X509_PURPOSE_SSL_CLIENT;

        $result = openssl_x509_checkpurpose($certResource, $purpose, []);

        if ($result !== true) {
            $error = openssl_error_string();
            Logger::error('System CA bundle verification failed', [
                'Error' => $error ?: 'unknown',
            ]);
            throw new ProtocolViolationException('Certificate verification failed: not trusted by system CA bundle');
        }

        Logger::debug('System CA bundle verification succeeded');
    }

    /**
     * Verify certificate using custom CA path/file
     */
    public function verifyWithCustomCa(
        Certificate $certificate,
        bool $isClient,
        ?string $caPath = null,
        ?string $caFile = null,
    ): void {
        Logger::debug('Verifying certificate with custom CA', [
            'CA Path' => $caPath ?? 'none',
            'CA File' => $caFile ?? 'none',
        ]);

        $certResource = $certificate->getResource();

        $caList = [];
        if ($caPath !== null) {
            if (!is_dir($caPath)) {
                throw new CryptoException("Custom CA path does not exist or is not a directory: {$caPath}");
            }
            $caList[] = $caPath;
        }
        if ($caFile !== null) {
            if (!is_file($caFile)) {
                throw new CryptoException("Custom CA file does not exist: {$caFile}");
            }
            $caList[] = $caFile;
        }

        if (empty($caList)) {
            throw new CryptoException('No CA path or file provided for custom CA verification');
        }

        $purpose = $isClient ? X509_PURPOSE_SSL_SERVER : X509_PURPOSE_SSL_CLIENT;
        $result = openssl_x509_checkpurpose($certResource, $purpose, $caList);

        if ($result !== true) {
            $error = openssl_error_string();
            Logger::error('Custom CA verification failed', [
                'Error' => $error ?: 'unknown',
                'CA Path' => $caPath,
                'CA File' => $caFile,
            ]);
            throw new ProtocolViolationException('Certificate verification failed: not trusted by custom CA');
        }

        Logger::debug('Custom CA verification succeeded');
    }

    /**
     * Match hostname against pattern (supports wildcards)
     */
    public function matchesHostname(string $hostname, string $pattern): bool
    {
        // Exact match
        if ($pattern === $hostname) {
            return true;
        }

        // Wildcard matching (*.example.com)
        if (str_starts_with($pattern, '*.')) {
            $domain = substr($pattern, 2);

            return str_ends_with($hostname, '.'.$domain);
        }

        return false;
    }
}
