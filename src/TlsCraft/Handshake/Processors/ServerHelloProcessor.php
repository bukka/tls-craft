<?php

namespace Php\TlsCraft\Messages\Processors;

use Php\TlsCraft\Crypto\ECDHKeyExchange;
use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Extensions\{KeyShareExtension, SupportedVersionsExtension};
use Php\TlsCraft\Messages\ExtensionType;
use Php\TlsCraft\Messages\ServerHello;
use Php\TlsCraft\Protocol\Version;

class ServerHelloProcessor extends MessageProcessor
{
    public function process(ServerHello $message): void
    {
        // Validate legacy version field (should be 1.2 for TLS 1.3)
        if ($message->version !== Version::TLS_1_2) {
            throw new ProtocolViolationException(
                "ServerHello legacy version must be TLS 1.2, got: " . $message->version->name
            );
        }

        // Validate cipher suite selection
        if (!in_array($message->cipherSuite->value, $this->config->cipherSuites)) {
            throw new ProtocolViolationException(
                "Server selected unsupported cipher suite: " . $message->cipherSuite->value
            );
        }

        // Validate compression method (must be null for TLS 1.3)
        if ($message->compressionMethod !== 0) {
            throw new ProtocolViolationException(
                "ServerHello compression method must be null (0) for TLS 1.3"
            );
        }

        // Set server random
        $this->context->setServerRandom($message->random);

        // Set negotiated cipher suite
        $this->context->setNegotiatedCipherSuite($message->cipherSuite);

        // Store the ServerHello message for transcript hash
        $this->context->addHandshakeMessage($message);

        // Process mandatory extensions
        $this->parseSupportedVersions($message);
        $this->parseKeyShare($message);

        // Derive handshake secrets now that we have server key share
        $this->deriveHandshakeSecrets();
    }

    private function parseSupportedVersions(ServerHello $message): void
    {
        /** @var SupportedVersionsExtension $ext */
        $ext = $message->getExtension(ExtensionType::SUPPORTED_VERSIONS);
        if (!$ext) {
            throw new ProtocolViolationException(
                "supported_versions extension missing in ServerHello"
            );
        }

        $versions = $ext->getVersions();
        if (count($versions) !== 1) {
            throw new ProtocolViolationException(
                "ServerHello supported_versions must contain exactly one version"
            );
        }

        $selectedVersion = $versions[0];
        if ($selectedVersion !== Version::TLS_1_3) {
            throw new ProtocolViolationException(
                "Server selected unsupported version: " . $selectedVersion->name
            );
        }

        // Confirm TLS 1.3 negotiation
        $this->context->setNegotiatedVersion(Version::TLS_1_3);
    }

    private function parseKeyShare(ServerHello $message): void
    {
        /** @var KeyShareExtension $ext */
        $ext = $message->getExtension(ExtensionType::KEY_SHARE);
        if (!$ext) {
            throw new ProtocolViolationException(
                "key_share extension missing in ServerHello"
            );
        }

        $keyShares = $ext->getKeyShares();
        if (count($keyShares) !== 1) {
            throw new ProtocolViolationException(
                "ServerHello key_share must contain exactly one key share"
            );
        }

        $serverKeyShare = $keyShares[0];

        // Verify server selected a group we offered
        $clientKeyShare = $this->context->getClientKeyShare();
        if (!$clientKeyShare) {
            throw new ProtocolViolationException(
                "No client key share found in context"
            );
        }

        if ($serverKeyShare->getGroup() !== $clientKeyShare->getGroup()) {
            throw new ProtocolViolationException(
                "Server selected different group than client offered: " .
                $serverKeyShare->getGroup()->getName()
            );
        }

        // Store server's key share
        $this->context->setServerKeyShare($serverKeyShare);
    }

    private function deriveHandshakeSecrets(): void
    {
        $clientKeyShare = $this->context->getClientKeyShare();
        $serverKeyShare = $this->context->getServerKeyShare();

        if (!$clientKeyShare || !$serverKeyShare) {
            throw new ProtocolViolationException(
                "Cannot derive handshake secrets: missing key shares"
            );
        }

        // Compute shared secret using ECDH
        $sharedSecret = $this->computeSharedSecret($clientKeyShare, $serverKeyShare);
        $this->context->setSharedSecret($sharedSecret);

        // Derive handshake traffic secrets
        $this->context->deriveHandshakeSecrets();
    }

    private function computeSharedSecret($clientKeyShare, $serverKeyShare): string
    {
        if ($this->context->isClient()) {
            // Client computes using client private key + server public key
            $clientPrivateKey = $this->context->getPrivateKey();
            return ECDHKeyExchange::computeSharedSecret(
                $clientPrivateKey,
                $serverKeyShare->getKeyExchange()
            );
        } else {
            // Server computes using server private key + client public key
            $serverPrivateKey = $this->context->getPrivateKey();
            return ECDHKeyExchange::computeSharedSecret(
                $serverPrivateKey,
                $clientKeyShare->getKeyExchange()
            );
        }
    }
}
