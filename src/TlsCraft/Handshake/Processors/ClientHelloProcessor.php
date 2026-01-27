<?php

namespace Php\TlsCraft\Handshake\Processors;

use Php\TlsCraft\Crypto\CipherSuite;
use Php\TlsCraft\Crypto\SignatureScheme;
use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Handshake\Extensions\AlpnExtension;
use Php\TlsCraft\Handshake\Extensions\KeyShareExtension;
use Php\TlsCraft\Handshake\Extensions\PreSharedKeyExtension;
use Php\TlsCraft\Handshake\Extensions\PskKeyExchangeModesExtension;
use Php\TlsCraft\Handshake\Extensions\ServerNameExtension;
use Php\TlsCraft\Handshake\Extensions\SignatureAlgorithmsExtension;
use Php\TlsCraft\Handshake\Extensions\SupportedVersionsExtension;
use Php\TlsCraft\Handshake\ExtensionType;
use Php\TlsCraft\Handshake\Messages\ClientHelloMessage;
use Php\TlsCraft\Logger;
use Php\TlsCraft\Protocol\Version;
use Php\TlsCraft\Session\PreSharedKey;

class ClientHelloProcessor extends MessageProcessor
{
    public function process(ClientHelloMessage $message): void
    {
        Logger::debug('ClientHelloProcessor: Starting processing', [
            'version' => sprintf('0x%04x', $message->version->value),
            'cipher_suites_count' => count($message->cipherSuites),
        ]);

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

        // Parse extensions in order
        $this->parseSupportedVersions($message);
        $this->parseServerNameIndication($message); // Parse SNI early (needed for PSK lookup)

        // Try PSK first (before cipher suite selection)
        $this->parsePskExtension($message);

        // Select cipher suite (may already be set by PSK)
        if (!$this->context->getNegotiatedCipherSuite()) {
            foreach ($message->cipherSuites as $cipher) {
                if (in_array($cipher, $this->context->getConfig()->getCipherSuites())) {
                    $this->context->setNegotiatedCipherSuite(CipherSuite::from($cipher));
                    Logger::debug('ClientHelloProcessor: Cipher suite selected', [
                        'cipher_suite' => CipherSuite::from($cipher)->name,
                    ]);
                    break;
                }
            }
        }

        // Key share is optional for PSK-only mode
        $this->parseKeyShare($message);

        // Signature algorithms only needed for full handshake
        if (!$this->context->isResuming()) {
            $this->parseSignatureAlgorithms($message);
        }

        $this->parseAlpn($message);

        $this->parseEarlyData($message);

        Logger::debug('ClientHelloProcessor: Processing complete', [
            'is_resuming' => $this->context->isResuming(),
            'cipher_suite' => $this->context->getNegotiatedCipherSuite()?->name,
        ]);
    }

    private function parseSupportedVersions(ClientHelloMessage $message): void
    {
        /** @var SupportedVersionsExtension $ext */
        $ext = $message->getExtension(ExtensionType::SUPPORTED_VERSIONS);
        if (!$ext) {
            throw new ProtocolViolationException('supported_versions extension required for TLS 1.3');
        }

        Logger::debug('ClientHelloProcessor: Supported versions', [
            'versions' => array_map(fn ($v) => sprintf('0x%04x', $v->value), $ext->getVersions()),
            'supports_tls13' => $ext->supportsVersion(Version::TLS_1_3),
        ]);

        if (!$ext->supportsVersion(Version::TLS_1_3)) {
            throw new ProtocolViolationException('Client does not support TLS 1.3');
        }

        $this->context->setNegotiatedVersion(Version::TLS_1_3);
    }

    private function parseServerNameIndication(ClientHelloMessage $message): void
    {
        /** @var ServerNameExtension $ext */
        $ext = $message->getExtension(ExtensionType::SERVER_NAME);
        if ($ext) {
            $serverName = $ext->getServerName();
            $this->context->setRequestedServerName($serverName);
            Logger::debug('ClientHelloProcessor: SNI extension present', [
                'server_name' => $serverName,
                'server_name_length' => strlen($serverName),
            ]);
        } else {
            Logger::debug('ClientHelloProcessor: No SNI extension in ClientHello');
        }
    }

    private function parsePskExtension(ClientHelloMessage $message): void
    {
        /** @var PreSharedKeyExtension $ext */
        $ext = $message->getExtension(ExtensionType::PRE_SHARED_KEY);
        if (!$ext) {
            Logger::debug('ClientHelloProcessor: No PSK extension in ClientHello');

            return;
        }

        Logger::debug('ClientHelloProcessor: PSK extension present', [
            'identity_count' => $ext->getIdentityCount(),
            'has_binders' => $ext->hasBinders(),
        ]);

        // Validate PSK key exchange modes are offered
        /** @var PskKeyExchangeModesExtension $modesExt */
        $modesExt = $message->getExtension(ExtensionType::PSK_KEY_EXCHANGE_MODES);
        if (!$modesExt) {
            Logger::debug('ClientHelloProcessor: PSK offered but no PSK key exchange modes');

            return;
        }

        $this->context->setPskKeyExchangeModes($modesExt->modes);

        // Get the requested server name (from SNI extension)
        $serverName = $this->context->getRequestedServerName();

        // Create PSK resolver
        $resolver = $this->config->createPskResolver();

        // Try to find a matching PSK
        $selectedPsk = null;
        $selectedIndex = null;

        foreach ($ext->identities as $index => $identity) {
            // Resolve PSK by identity, passing server name for validation
            $psk = $resolver->resolve($identity->identity, $serverName);
            if ($psk === null) {
                Logger::debug('ClientHelloProcessor: PSK identity not found', [
                    'index' => $index,
                ]);
                continue;
            }

            Logger::debug('ClientHelloProcessor: PSK identity resolved', [
                'index' => $index,
                'cipher_suite' => $psk->cipherSuite->name,
            ]);

            // Verify cipher suite is compatible
            if (!in_array($psk->cipherSuite->value, $message->cipherSuites, true)) {
                Logger::debug('ClientHelloProcessor: PSK cipher suite not in client offer', [
                    'psk_cipher' => $psk->cipherSuite->name,
                ]);
                continue;
            }

            // Verify binder
            if ($this->verifyPskBinder($ext, $psk, $ext->binders[$index])) {
                $selectedPsk = $psk;
                $selectedIndex = $index;
                Logger::debug('ClientHelloProcessor: PSK binder verified', [
                    'index' => $index,
                ]);
                break;
            } else {
                Logger::error('ClientHelloProcessor: PSK binder verification failed', [
                    'index' => $index,
                ]);
            }
        }

        if ($selectedPsk !== null) {
            // Update cipher suite to match PSK and derive early secrets
            $this->context->setNegotiatedCipherSuite($selectedPsk->cipherSuite);
            $this->context->deriveEarlySecret($selectedPsk->secret);

            $this->context->setSelectedPsk($selectedPsk, $selectedIndex);
            Logger::debug('ClientHelloProcessor: PSK selected for resumption', [
                'index' => $selectedIndex,
                'cipher_suite' => $selectedPsk->cipherSuite->name,
            ]);
        } else {
            Logger::debug('ClientHelloProcessor: No valid PSK found');
        }
    }

    private function verifyPskBinder(
        PreSharedKeyExtension $pskExt,
        PreSharedKey $psk,
        string $receivedBinder,
    ): bool {
        // Get the wire format of ClientHello (WITH handshake header, already in transcript)
        $transcript = $this->context->getHandshakeTranscript();
        $clientHelloWire = $transcript->getLast();

        // Strip binders from ClientHello using PSK cipher suite hash length
        $binderLength = $psk->cipherSuite->getHashLength();
        $partialClientHello = $pskExt->stripBindersFromClientHello($clientHelloWire, $binderLength);

        // Determine if this is an external PSK (vs resumption PSK)
        $isExternal = $this->isExternalPsk($psk);

        // Calculate expected binder using partial ClientHello
        $calculator = $this->context->getPskBinderCalculator();
        $expectedBinder = $calculator->calculateBinder(
            $psk,
            $partialClientHello,
            $isExternal,
            '', // No previous transcript for initial ClientHello
        );

        $matches = hash_equals($expectedBinder, $receivedBinder);

        Logger::debug('ClientHelloProcessor: Binder verification', [
            'is_external' => $isExternal,
            'cipher_suite' => $psk->cipherSuite->name,
            'binder_length' => $binderLength,
            'full_ch_length' => strlen($clientHelloWire),
            'partial_ch_length' => strlen($partialClientHello),
            'expected' => bin2hex($expectedBinder),
            'received' => bin2hex($receivedBinder),
            'match' => $matches,
        ]);

        return $matches;
    }

    /**
     * Check if PSK is an external (manually configured) PSK
     */
    private function isExternalPsk(PreSharedKey $psk): bool
    {
        foreach ($this->config->getExternalPsks() as $externalPsk) {
            if ($psk === $externalPsk) {
                return true;
            }
        }

        return false;
    }

    private function parseKeyShare(ClientHelloMessage $message): void
    {
        /** @var KeyShareExtension $ext */
        $ext = $message->getExtension(ExtensionType::KEY_SHARE);

        // If PSK-only mode is selected, key share is optional
        if (!$ext && $this->context->isResuming() && $this->context->supportsPskOnly()) {
            Logger::debug('ClientHelloProcessor: No key share (PSK-only mode)');

            return;
        }

        if (!$ext) {
            throw new ProtocolViolationException('key_share extension missing');
        }

        $clientKeyShares = $ext->getKeyShares();
        $supportedGroups = $this->context->getConfig()->getSupportedGroups();

        Logger::debug('ClientHelloProcessor: Key shares', [
            'client_key_shares' => array_map(fn ($ks) => $ks->getGroup()->getName(), $clientKeyShares),
            'supported_groups' => $supportedGroups,
        ]);

        $selectedGroup = null;
        foreach ($clientKeyShares as $keyShare) {
            if (in_array($keyShare->getGroup()->getName(), $supportedGroups)) {
                $selectedGroup = $keyShare->getGroup();
                $this->context->setClientKeyShare($keyShare);
                Logger::debug('ClientHelloProcessor: Key share selected', [
                    'group' => $selectedGroup->getName(),
                ]);
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

        Logger::debug('ClientHelloProcessor: Signature algorithms', [
            'client_algorithms_count' => count($clientSigAlgs),
            'client_algorithms' => array_map(fn ($s) => $s->name, array_slice($clientSigAlgs, 0, 5)),
        ]);

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
        $certificateChain = $this->context->getServerCertificateChain();
        if (!$certificateChain) {
            Logger::error('No certificate chain configured');

            return null;
        }

        // Get algorithms supported by the leaf certificate
        $certificateSchemes = $certificateChain->getSupportedSignatureSchemes();

        // Get server's configured algorithms
        $serverSchemes = $this->context->getConfig()->getSignatureAlgorithms();

        Logger::debug('ClientHelloProcessor: Signature scheme selection', [
            'certificate_key_type' => $certificateChain->getKeyTypeName(),
            'certificate_schemes' => array_map(fn ($s) => $s->name, $certificateSchemes),
            'client_sig_algs' => array_map(fn ($s) => $s->name, $clientSigAlgs),
            'server_config_sig_algs' => $serverSchemes,
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
                    Logger::debug('ClientHelloProcessor: Signature scheme selected', [
                        'scheme' => $serverScheme->name,
                    ]);

                    return $serverScheme;
                }
            }
        }

        Logger::error('No matching signature scheme found');

        return null;
    }

    private function parseAlpn(ClientHelloMessage $message): void
    {
        /** @var AlpnExtension $ext */
        $ext = $message->getExtension(ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
        if ($ext) {
            $clientProtocols = $ext->getProtocols();
            $this->context->setClientOfferedProtocols($clientProtocols);
            Logger::debug('ClientHelloProcessor: ALPN extension present', [
                'client_protocols' => $clientProtocols,
            ]);

            $alpnProtocol = $this->selectALPNProtocol($clientProtocols);
            if ($alpnProtocol !== null) {
                $this->context->setSelectedProtocol($alpnProtocol);
                Logger::debug('ClientHelloProcessor: ALPN protocol selected', [
                    'protocol' => $alpnProtocol,
                ]);
            } else {
                Logger::debug('ClientHelloProcessor: No ALPN protocol selected');
            }
        } else {
            Logger::debug('ClientHelloProcessor: No ALPN extension in ClientHello');
        }
    }

    private function selectALPNProtocol(array $clientProtocols): ?string
    {
        // If server has no configured protocols, don't select anything
        if (empty($this->config->getSupportedProtocols())) {
            Logger::debug('ClientHelloProcessor: No server ALPN protocols configured');

            return null;
        }

        // Standard first-match selection
        foreach ($clientProtocols as $clientProtocol) {
            if (in_array($clientProtocol, $this->config->getSupportedProtocols())) {
                return $clientProtocol;
            }
        }

        Logger::debug('ClientHelloProcessor: No ALPN protocol match', [
            'client_protocols' => $clientProtocols,
            'server_protocols' => $this->config->getSupportedProtocols(),
        ]);

        return null;
    }

    /**
     * Parse early_data extension from ClientHello
     *
     * RFC 8446 Section 4.2.10: The "early_data" extension in ClientHello
     * indicates the client's intention to send early data.
     */
    private function parseEarlyData(ClientHelloMessage $message): void
    {
        $ext = $message->getExtension(ExtensionType::EARLY_DATA);

        if ($ext) {
            // Client is attempting to send early data
            $this->context->setEarlyDataAttempted(true);

            Logger::debug('ClientHelloProcessor: Early data extension present', [
                'client_attempting_early_data' => true,
            ]);
        } else {
            Logger::debug('ClientHelloProcessor: No early_data extension in ClientHello');
        }
    }
}
