<?php

namespace Php\TlsCraft\Handshake\Processors;

use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Handshake\Extensions\AlpnExtension;
use Php\TlsCraft\Handshake\Extensions\KeyShareExtension;
use Php\TlsCraft\Handshake\Extensions\ServerNameExtension;
use Php\TlsCraft\Handshake\Extensions\SignatureAlgorithmsExtension;
use Php\TlsCraft\Handshake\Extensions\SupportedVersionsExtension;
use Php\TlsCraft\Handshake\ExtensionType;
use Php\TlsCraft\Handshake\Messages\ClientHello;
use Php\TlsCraft\Logger;
use Php\TlsCraft\Protocol\Version;

class ClientHelloProcessor extends MessageProcessor
{
    public function process(ClientHello $message): void
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

        // Set session ID for ServerHello
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

    private function parseSupportedVersions(ClientHello $message): void
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

    private function parseKeyShare(ClientHello $message): void
    {
        /** @var KeyShareExtension $ext */
        $ext = $message->getExtension(ExtensionType::KEY_SHARE);
        if (!$ext) {
            throw new ProtocolViolationException('key_share extension missing');
        }

        $clientKeyShares = $ext->getKeyShares();
        $supportedGroups = $this->context->getConfig()->getSupportedGroups();

        Logger::debug('ClientHello key shares', [
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

    private function parseSignatureAlgorithms(ClientHello $message): void
    {
        /** @var SignatureAlgorithmsExtension $ext */
        $ext = $message->getExtension(ExtensionType::SIGNATURE_ALGORITHMS);
        if (!$ext) {
            throw new ProtocolViolationException('signature_algorithms extension missing');
        }

        $clientSigAlgs = $ext->getSignatureAlgorithms();
        $supportedSigAlgs = $this->context->getConfig()->getSignatureAlgorithms();

        Logger::debug('ClientHello signature algorithms', [
            'Client sig algs' => $clientSigAlgs,
            'Supported sig algs' => $supportedSigAlgs,
        ]);

        $selectedSigAlg = null;
        foreach ($clientSigAlgs as $sigAlg) {
            if (in_array($sigAlg->getName(), $supportedSigAlgs)) {
                $selectedSigAlg = $sigAlg;
                break;
            }
        }

        if (!$selectedSigAlg) {
            throw new ProtocolViolationException('No supported signature algorithm found');
        }
        $this->context->setNegotiatedSignatureScheme($selectedSigAlg);
    }

    private function parseServerNameIndication(ClientHello $message): void
    {
        /** @var ServerNameExtension $ext */
        $ext = $message->getExtension(ExtensionType::SERVER_NAME);
        if ($ext) {
            $serverName = $ext->getServerName();
            $this->context->setRequestedServerName($serverName);
        }
    }

    private function parseAlpn(ClientHello $message): void
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
