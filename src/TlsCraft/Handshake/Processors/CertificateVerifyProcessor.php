<?php

namespace Php\TlsCraft\Handshake\Processors;

use Php\TlsCraft\Crypto\SignatureScheme;
use Php\TlsCraft\Exceptions\{CryptoException, ProtocolViolationException};
use Php\TlsCraft\Handshake\Messages\CertificateVerify;

use const OPENSSL_ALGO_SHA256;
use const OPENSSL_ALGO_SHA384;
use const OPENSSL_ALGO_SHA512;
use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_RSA;
use const OPENSSL_PKCS1_PSS_PADDING;

class CertificateVerifyProcessor extends MessageProcessor
{
    public function process(CertificateVerify $message): void
    {
        // Validate signature algorithm
        $this->validateSignatureAlgorithm($message->algorithm);

        // Verify the signature
        $this->verifySignature($message->algorithm, $message->signature);

        // Mark certificate as verified in context
        $this->context->setCertificateVerified(true);
    }

    private function validateSignatureAlgorithm(SignatureScheme $algorithm): void
    {
        // Check if the algorithm was offered by us in signature_algorithms extension
        $supportedAlgorithms = $this->config->getSignatureAlgorithms();

        // Convert algorithm names to SignatureScheme objects for comparison
        $supportedSchemes = array_map(
            fn($name) => SignatureScheme::fromName($name),
            $supportedAlgorithms
        );

        if (!in_array($algorithm, $supportedSchemes, true)) {
            throw new ProtocolViolationException("Server used unsupported signature algorithm: {$algorithm->getName()}");
        }

        // Validate algorithm is appropriate for the certificate type
        $peerPublicKey = $this->context->getPeerPublicKey();
        if (!$peerPublicKey) {
            throw new ProtocolViolationException('No peer public key available for signature verification');
        }

        $this->validateAlgorithmForKey($algorithm, $peerPublicKey);
    }

    private function validateAlgorithmForKey(SignatureScheme $algorithm, $publicKey): void
    {
        $keyDetails = openssl_pkey_get_details($publicKey);
        if (!$keyDetails) {
            throw new CryptoException('Failed to get public key details');
        }

        $keyType = $keyDetails['type'];

        switch ($keyType) {
            case OPENSSL_KEYTYPE_RSA:
                if (!$algorithm->isRSA()) {
                    throw new ProtocolViolationException("RSA key cannot be used with signature algorithm: {$algorithm->getName()}");
                }
                break;

            case OPENSSL_KEYTYPE_EC:
                if (!$algorithm->isECDSA()) {
                    throw new ProtocolViolationException("ECDSA key cannot be used with signature algorithm: {$algorithm->getName()}");
                }
                break;

            default:
                // Check for EdDSA keys if supported
                if ($algorithm->isEdDSA()) {
                    // EdDSA verification will be handled by OpenSSL
                    break;
                }
                throw new ProtocolViolationException('Unsupported public key type for signature verification');
        }
    }

    private function verifySignature(SignatureScheme $algorithm, string $signature): void
    {
        // Build the signature context according to TLS 1.3 spec
        $signatureContext = $this->buildSignatureContext();

        // Get the peer's public key
        $peerPublicKey = $this->context->getPeerPublicKey();
        if (!$peerPublicKey) {
            throw new ProtocolViolationException('No peer public key available for signature verification');
        }

        // Verify signature using appropriate method based on algorithm
        $isValid = $this->performSignatureVerification(
            $signatureContext,
            $signature,
            $peerPublicKey,
            $algorithm,
        );

        if (!$isValid) {
            throw new ProtocolViolationException('CertificateVerify signature verification failed');
        }
    }

    private function buildSignatureContext(): string
    {
        // TLS 1.3 signature context format:
        // - 64 spaces (0x20)
        // - Context string
        // - 0x00 separator
        // - Transcript hash

        $contextString = $this->getContextString();
        $transcriptHash = $this->context->getTranscriptHash();

        return str_repeat("\x20", 64) .
            $contextString .
            "\x00" .
            $transcriptHash;
    }

    private function getContextString(): string
    {
        if ($this->context->isClient()) {
            // We're client processing server's CertificateVerify
            return 'TLS 1.3, server CertificateVerify';
        } else {
            // We're server processing client's CertificateVerify
            return 'TLS 1.3, client CertificateVerify';
        }
    }

    private function performSignatureVerification(
        string $data,
        string $signature,
        $publicKey,
        SignatureScheme $algorithm,
    ): bool {
        // Get the OpenSSL algorithm constant and padding type
        [$opensslAlgo, $padding] = $this->getOpenSSLParameters($algorithm);

        if ($opensslAlgo === null) {
            throw new ProtocolViolationException(
                "Signature verification not implemented for algorithm: {$algorithm->getName()}"
            );
        }

        $result = openssl_verify($data, $signature, $publicKey, $opensslAlgo, $padding);

        if ($result === -1) {
            // Error occurred
            $error = openssl_error_string();
            throw new CryptoException("OpenSSL verification error: {$error}");
        }

        return $result === 1;
    }

    /**
     * Get OpenSSL algorithm constant and padding type for a signature scheme
     *
     * @return array{int|string|null, int} [algorithm, padding]
     */
    private function getOpenSSLParameters(SignatureScheme $algorithm): array
    {
        return match($algorithm) {
            // RSA PKCS#1 v1.5 - use default padding (0)
            SignatureScheme::RSA_PKCS1_SHA256 => [OPENSSL_ALGO_SHA256, 0],
            SignatureScheme::RSA_PKCS1_SHA384 => [OPENSSL_ALGO_SHA384, 0],
            SignatureScheme::RSA_PKCS1_SHA512 => [OPENSSL_ALGO_SHA512, 0],

            // ECDSA - padding parameter is ignored for EC keys
            SignatureScheme::ECDSA_SECP256R1_SHA256 => [OPENSSL_ALGO_SHA256, 0],
            SignatureScheme::ECDSA_SECP384R1_SHA384 => [OPENSSL_ALGO_SHA384, 0],
            SignatureScheme::ECDSA_SECP521R1_SHA512 => [OPENSSL_ALGO_SHA512, 0],

            // RSA-PSS - use PSS padding constant from PHP 8.5
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PSS_PSS_SHA256 => [OPENSSL_ALGO_SHA256, OPENSSL_PKCS1_PSS_PADDING],

            SignatureScheme::RSA_PSS_RSAE_SHA384,
            SignatureScheme::RSA_PSS_PSS_SHA384 => [OPENSSL_ALGO_SHA384, OPENSSL_PKCS1_PSS_PADDING],

            SignatureScheme::RSA_PSS_RSAE_SHA512,
            SignatureScheme::RSA_PSS_PSS_SHA512 => [OPENSSL_ALGO_SHA512, OPENSSL_PKCS1_PSS_PADDING],

            // EdDSA - if supported by OpenSSL
            SignatureScheme::ED25519 => ['Ed25519', 0],
            SignatureScheme::ED448 => ['Ed448', 0],

            default => [null, 0],
        };
    }
}
