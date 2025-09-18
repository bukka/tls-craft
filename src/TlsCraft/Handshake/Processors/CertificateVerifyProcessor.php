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

class CertificateVerifyProcessor extends MessageProcessor
{
    public function process(CertificateVerify $message): void
    {
        // Store the message for transcript hash
        $this->context->addHandshakeMessage($message);

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

        if (!in_array($algorithm, $supportedAlgorithms)) {
            throw new ProtocolViolationException("Server used unsupported signature algorithm: {$algorithm->name}");
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
                if (!$this->isRSAAlgorithm($algorithm)) {
                    throw new ProtocolViolationException("RSA key cannot be used with signature algorithm: {$algorithm->name}");
                }
                break;

            case OPENSSL_KEYTYPE_EC:
                if (!$this->isECDSAAlgorithm($algorithm)) {
                    throw new ProtocolViolationException("ECDSA key cannot be used with signature algorithm: {$algorithm->name}");
                }
                break;

            default:
                throw new ProtocolViolationException('Unsupported public key type for signature verification');
        }
    }

    private function isRSAAlgorithm(SignatureScheme $algorithm): bool
    {
        return match($algorithm) {
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PSS_RSAE_SHA384,
            SignatureScheme::RSA_PSS_RSAE_SHA512,
            SignatureScheme::RSA_PSS_PSS_SHA256,
            SignatureScheme::RSA_PSS_PSS_SHA384,
            SignatureScheme::RSA_PSS_PSS_SHA512 => true,
            default => false,
        };
    }

    private function isECDSAAlgorithm(SignatureScheme $algorithm): bool
    {
        return match($algorithm) {
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            SignatureScheme::ECDSA_SECP384R1_SHA384,
            SignatureScheme::ECDSA_SECP521R1_SHA512 => true,
            default => false,
        };
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

        return str_repeat("\x20", 64).
            $contextString.
            "\x00".
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
        return match($algorithm) {
            // RSA PKCS#1 v1.5
            SignatureScheme::RSA_PKCS1_SHA256 => openssl_verify($data, $signature, $publicKey, OPENSSL_ALGO_SHA256) === 1,
            SignatureScheme::RSA_PKCS1_SHA384 => openssl_verify($data, $signature, $publicKey, OPENSSL_ALGO_SHA384) === 1,
            SignatureScheme::RSA_PKCS1_SHA512 => openssl_verify($data, $signature, $publicKey, OPENSSL_ALGO_SHA512) === 1,

            // ECDSA
            SignatureScheme::ECDSA_SECP256R1_SHA256 => openssl_verify($data, $signature, $publicKey, OPENSSL_ALGO_SHA256) === 1,
            SignatureScheme::ECDSA_SECP384R1_SHA384 => openssl_verify($data, $signature, $publicKey, OPENSSL_ALGO_SHA384) === 1,
            SignatureScheme::ECDSA_SECP521R1_SHA512 => openssl_verify($data, $signature, $publicKey, OPENSSL_ALGO_SHA512) === 1,

            // RSA-PSS
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PSS_PSS_SHA256 => $this->verifyRSAPSS($data, $signature, $publicKey, 'sha256'),
            SignatureScheme::RSA_PSS_RSAE_SHA384,
            SignatureScheme::RSA_PSS_PSS_SHA384 => $this->verifyRSAPSS($data, $signature, $publicKey, 'sha384'),
            SignatureScheme::RSA_PSS_RSAE_SHA512,
            SignatureScheme::RSA_PSS_PSS_SHA512 => $this->verifyRSAPSS($data, $signature, $publicKey, 'sha512'),

            default => throw new ProtocolViolationException("Signature verification not implemented for algorithm: {$algorithm->name}"),
        };
    }

    private function verifyRSAPSS(string $data, string $signature, $publicKey, string $hashAlg): bool
    {
        // RSA-PSS signature verification
        // Note: OpenSSL's openssl_verify() may not directly support PSS padding
        // This is a simplified implementation - production code would need proper PSS handling

        $keyDetails = openssl_pkey_get_details($publicKey);
        if (!$keyDetails || $keyDetails['type'] !== OPENSSL_KEYTYPE_RSA) {
            return false;
        }

        // For now, fall back to basic verification
        // In production, you'd need to implement proper PSS padding verification
        $openSSLAlgo = match($hashAlg) {
            'sha256' => OPENSSL_ALGO_SHA256,
            'sha384' => OPENSSL_ALGO_SHA384,
            'sha512' => OPENSSL_ALGO_SHA512,
            default => throw new CryptoException("Unsupported hash algorithm: {$hashAlg}"),
        };

        return openssl_verify($data, $signature, $publicKey, $openSSLAlgo) === 1;
    }
}
