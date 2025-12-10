<?php

namespace Php\TlsCraft\Handshake\Processors;

use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Crypto\SignatureScheme;
use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Handshake\Extensions\AlpnExtension;
use Php\TlsCraft\Handshake\Extensions\KeyShareExtension;
use Php\TlsCraft\Handshake\Extensions\ServerNameExtension;
use Php\TlsCraft\Handshake\Extensions\SignatureAlgorithmsExtension;
use Php\TlsCraft\Handshake\Extensions\SupportedVersionsExtension;
use Php\TlsCraft\Handshake\ExtensionType;
use Php\TlsCraft\Handshake\Messages\ClientHelloMessage;
use Php\TlsCraft\Logger;
use Php\TlsCraft\Protocol\Version;

class ClientHelloProcessor extends MessageProcessor
{
    public function process(ClientHelloMessage $message): void
    {
        // Validate version (should be always legacy TLS 1.2)
        if ($message->version != Version::TLS_1_2) {
            throw new ProtocolViolationException('Unsupported TLS version');
        }

        // Validate cipher suites
        if (empty($message->cipherSuites)) {
            throw new ProtocolViolationException('No cipher suites offered');
        }

        // Validate compression methods
        if (!in_array(0, $message->compressionMethods)) {
            throw new ProtocolViolationException('Null compression method not supported');
        }

        // Set session ID for ServerHelloMessage
        $this->context->setClientHelloSessionId($message->sessionId);

        // Set client random
        $this->context->setClientRandom($message->random);

        // Select a cipher suite
        foreach ($message->cipherSuites as $cipher) {
            if (in_array($cipher, $this->context->getConfig()->getCipherSuites())) {
                $this->context->setNegotiatedCipherSuite(CipherSuite::from($cipher));
                break;
            }
        }

        $this->parseSupportedVersions($message);
        $this->parseKeyShare($message);
        $this->parseSignatureAlgorithms($message);
        $this->parseServerNameIndication($message);
        $this->parseAlpn($message);
    }

    private function parseSupportedVersions(ClientHelloMessage $message): void
    {
        /** @var SupportedVersionsExtension $ext */
        $ext = $message->getExtension(ExtensionType::SUPPORTED_VERSIONS);
        if (!$ext) {
            throw new ProtocolViolationException('supported_versions extension required for TLS 1.3');
        }

        if (!$ext->supportsVersion(Version::TLS_1_3)) {
            throw new ProtocolViolationException('Client does not support TLS 1.3');
        }

        $this->context->setNegotiatedVersion(Version::TLS_1_3);
    }

    private function parseKeyShare(ClientHelloMessage $message): void
    {
        /** @var KeyShareExtension $ext */
        $ext = $message->getExtension(ExtensionType::KEY_SHARE);
        if (!$ext) {
            throw new ProtocolViolationException('key_share extension missing');
        }

        $clientKeyShares = $ext->getKeyShares();
        $supportedGroups = $this->context->getConfig()->getSupportedGroups();

        Logger::debug('ClientHelloMessage key shares', [
            'Client key shares' => $clientKeyShares,
            'Supported groups' => $supportedGroups,
        ]);

        $selectedGroup = null;
        foreach ($clientKeyShares as $keyShare) {
            if (in_array($keyShare->getGroup()->getName(), $supportedGroups)) {
                $selectedGroup = $keyShare->getGroup();
                $this->context->setClientKeyShare($keyShare);
                break;
            }
        }

        if (!$selectedGroup) {
            throw new ProtocolViolationException('No supported key exchange group found');
        }
    }

    private function parseSignatureAlgorithms(ClientHelloMessage $message): void
    {
        /** @var SignatureAlgorithmsExtension $ext */
        $ext = $message->getExtension(ExtensionType::SIGNATURE_ALGORITHMS);
        if (!$ext) {
            throw new ProtocolViolationException('signature_algorithms extension missing');
        }

        $clientSigAlgs = $ext->getSignatureAlgorithms();

        // Store client's signature algorithms for later use in CertificateVerify
        $this->context->setClientSignatureAlgorithms($clientSigAlgs);

        // Select signature scheme for CertificateVerify based on certificate
        $selectedSigAlg = $this->selectSignatureScheme($clientSigAlgs);

        if (!$selectedSigAlg) {
            throw new ProtocolViolationException('No compatible signature algorithm found for certificate');
        }

        $this->context->setNegotiatedSignatureScheme($selectedSigAlg);
    }

    private function selectSignatureScheme(array $clientSigAlgs): ?SignatureScheme
    {
        $certificateChain = $this->context->getCertificateChain();
        if (!$certificateChain) {
            Logger::error('No certificate chain configured');
            return null;
        }

        // Get algorithms supported by the leaf certificate
        $certificateSchemes = $certificateChain->getSupportedSignatureSchemes();

        // Get server's configured algorithms
        $serverSchemes = $this->context->getConfig()->getSignatureAlgorithms();

        Logger::debug('ClientHelloMessage signature algorithms', [
            'Certificate key type' => $certificateChain->getKeyTypeName(),
            'Certificate schemes' => array_map(fn($s) => $s->name, $certificateSchemes),
            'Client sig algs' => array_map(fn($s) => $s->name, $clientSigAlgs),
            'Server config sig algs' => $serverSchemes,
        ]);

        // Find first match: must be supported by certificate, server config, and client
        // Priority order: server config (our preference)
        foreach ($serverSchemes as $serverSchemeName) {
            // Convert string to SignatureScheme enum
            $serverScheme = null;
            foreach ($certificateSchemes as $certScheme) {
                if ($certScheme->getName() === $serverSchemeName) {
                    $serverScheme = $certScheme;
                    break;
                }
            }

            if (!$serverScheme) {
                // Server config includes an algorithm not supported by our certificate
                continue;
            }

            // Check if client supports this scheme
            foreach ($clientSigAlgs as $clientScheme) {
                if ($serverScheme === $clientScheme) {
                    Logger::debug('Signature scheme selected', [
                        'Scheme' => $serverScheme->name,
                    ]);
                    return $serverScheme;
                }
            }
        }

        Logger::error('No matching signature scheme found');
        return null;
    }

    private function parseServerNameIndication(ClientHelloMessage $message): void
    {
        /** @var ServerNameExtension $ext */
        $ext = $message->getExtension(ExtensionType::SERVER_NAME);
        if ($ext) {
            $serverName = $ext->getServerName();
            $this->context->setRequestedServerName($serverName);
        }
    }

    private function parseAlpn(ClientHelloMessage $message): void
    {
        /** @var AlpnExtension $ext */
        $ext = $message->getExtension(ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
        if ($ext) {
            $this->context->setClientOfferedProtocols($ext->getProtocols());
            $alpnProtocol = $this->selectALPNProtocol($ext->getProtocols());
            if ($alpnProtocol !== null) {
                $this->context->setSelectedProtocol($alpnProtocol);
            }
        }
    }

    private function selectALPNProtocol(array $clientProtocols): ?string
    {
        // If server has no configured protocols, don't select anything
        if (empty($this->config->getSupportedProtocols())) {
            return null;
        }

        // Standard first-match selection
        foreach ($clientProtocols as $clientProtocol) {
            if (in_array($clientProtocol, $this->config->getSupportedProtocols())) {
                return $clientProtocol;
            }
        }

        return null;
    }
}
