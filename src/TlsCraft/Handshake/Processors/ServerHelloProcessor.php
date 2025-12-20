<?php

namespace Php\TlsCraft\Handshake\Processors;

use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Handshake\Extensions\{KeyShareExtension, PreSharedKeyExtension, SupportedVersionsExtension};
use Php\TlsCraft\Handshake\ExtensionType;
use Php\TlsCraft\Handshake\Messages\ServerHelloMessage;
use Php\TlsCraft\Protocol\Version;

/**
 * Process ServerHelloMessage message which happens on the client side after ClientHelloMessage
 */
class ServerHelloProcessor extends MessageProcessor
{
    public function process(ServerHelloMessage $message): void
    {
        // Validate legacy version field (should be 1.2 for TLS 1.3)
        if ($message->version !== Version::TLS_1_2) {
            throw new ProtocolViolationException('ServerHelloMessage legacy version must be TLS 1.2, got: '.$message->version->name);
        }

        // Validate cipher suite selection
        if (!in_array($message->cipherSuite->value, $this->config->getCipherSuites())) {
            throw new ProtocolViolationException('Server selected unsupported cipher suite: '.$message->cipherSuite->value);
        }

        // Validate compression method (must be null for TLS 1.3)
        if ($message->compressionMethod !== 0) {
            throw new ProtocolViolationException('ServerHelloMessage compression method must be null (0) for TLS 1.3');
        }

        // Process mandatory extensions
        $this->parseSupportedVersions($message);
        $this->parseKeyShare($message);

        // Set server random
        $this->context->setServerRandom($message->random);

        // Set negotiated cipher suite
        $this->context->setNegotiatedCipherSuite($message->cipherSuite);

        // Check if server selected PSK and derive early secret accordingly
        $this->processPskSelection($message);

        // Derive handshake secrets now that we have server key share
        $this->deriveHandshakeSecrets();
    }

    private function parseSupportedVersions(ServerHelloMessage $message): void
    {
        /** @var SupportedVersionsExtension $ext */
        $ext = $message->getExtension(ExtensionType::SUPPORTED_VERSIONS);
        if (!$ext) {
            throw new ProtocolViolationException('supported_versions extension missing in ServerHelloMessage');
        }

        $versions = $ext->getVersions();
        if (count($versions) !== 1) {
            throw new ProtocolViolationException('ServerHelloMessage supported_versions must contain exactly one version');
        }

        $selectedVersion = $versions[0];
        if ($selectedVersion !== Version::TLS_1_3) {
            throw new ProtocolViolationException('Server selected unsupported version: '.$selectedVersion->name);
        }

        // Confirm TLS 1.3 negotiation
        $this->context->setNegotiatedVersion(Version::TLS_1_3);
    }

    private function parseKeyShare(ServerHelloMessage $message): void
    {
        /** @var KeyShareExtension $ext */
        $ext = $message->getExtension(ExtensionType::KEY_SHARE);
        if (!$ext) {
            throw new ProtocolViolationException('key_share extension missing in ServerHelloMessage');
        }

        $keyShares = $ext->getKeyShares();
        if (count($keyShares) !== 1) {
            throw new ProtocolViolationException('ServerHelloMessage key_share must contain exactly one key share');
        }

        $serverKeyShare = $keyShares[0];

        // Verify server selected a group we support
        $clientKeyPair = $this->context->getKeyPairForGroup($serverKeyShare->getGroup());
        if (!$clientKeyPair) {
            throw new ProtocolViolationException("Server selected group we don't have a key pair for: ".$serverKeyShare->getGroup()->getName());
        }

        // Store server's key share
        $this->context->setServerKeyShare($serverKeyShare);
    }

    private function processPskSelection(ServerHelloMessage $message): void
    {
        /** @var PreSharedKeyExtension|null $pskExtension */
        $pskExtension = $message->getExtension(ExtensionType::PRE_SHARED_KEY);

        if ($pskExtension === null) {
            // No PSK selected - standard (EC)DHE handshake
            // Derive early secret with zeros (default behavior)
            $this->context->deriveEarlySecret();

            return;
        }

        // Server selected a PSK
        $selectedIndex = $pskExtension->selectedIdentity;
        $offeredPsks = $this->context->getOfferedPsks();

        if (empty($offeredPsks)) {
            throw new ProtocolViolationException('Server selected PSK but client did not offer any PSKs');
        }

        if (!isset($offeredPsks[$selectedIndex])) {
            throw new ProtocolViolationException("Server selected invalid PSK index: {$selectedIndex}");
        }

        $selectedPsk = $offeredPsks[$selectedIndex];

        // Mark as resuming and store selected PSK
        $this->context->setSelectedPsk($selectedPsk, $selectedIndex);

        // Derive early secret with the selected PSK's secret
        $this->context->deriveEarlySecret($selectedPsk->secret);
    }

    private function deriveHandshakeSecrets(): void
    {
        $serverKeyShare = $this->context->getServerKeyShare();
        if (!$serverKeyShare) {
            throw new ProtocolViolationException('Cannot derive handshake secrets: missing server key share');
        }

        // Get our key pair for the selected group
        $clientKeyPair = $this->context->getKeyPairForGroup($serverKeyShare->getGroup());
        if (!$clientKeyPair) {
            throw new ProtocolViolationException('No client key pair found for selected group');
        }

        // Compute shared secret using our key pair
        $sharedSecret = $clientKeyPair->computeSharedSecret($serverKeyShare->getKeyExchange());
        $this->context->setSharedSecret($sharedSecret);

        // Derive handshake traffic secrets
        $this->context->deriveHandshakeSecrets();
    }
}
