<?php

namespace Php\TlsCraft\Handshake\Processors;

use Php\TlsCraft\Exceptions\ProtocolViolationException;
use Php\TlsCraft\Handshake\Extensions\{
    ALPNExtension,
    ServerNameExtension,
    SupportedGroupsExtension
};
use Php\TlsCraft\Handshake\Messages\EncryptedExtensions;
use Php\TlsCraft\Handshake\ExtensionType;

class EncryptedExtensionsProcessor extends MessageProcessor
{
    public function process(EncryptedExtensions $message): void
    {
        // EncryptedExtensions can be empty - that's valid
        // Just validate that any extensions present are allowed in EncryptedExtensions

        $this->validateAllowedExtensions($message);

        // Store the message for transcript hash
        $this->context->addHandshakeMessage($message);

        // Process extensions that might be present
        $this->parseServerNameExtension($message);
        $this->parseALPNExtension($message);
        $this->parseSupportedGroupsExtension($message);

        // Any other extensions are handled generically or ignored
    }

    private function validateAllowedExtensions(EncryptedExtensions $message): void
    {
        foreach ($message->extensions as $extension) {
            $extensionType = ExtensionType::from($extension->type->value);

            if (!$extensionType->isAllowedInEncryptedExtensions()) {
                throw new ProtocolViolationException(
                    "Extension {$extensionType->getName()} not allowed in EncryptedExtensions"
                );
            }
        }
    }

    private function parseServerNameExtension(EncryptedExtensions $message): void
    {
        /** @var ServerNameExtension $ext */
        $ext = $message->getExtension(ExtensionType::SERVER_NAME);
        if ($ext) {
            // Server Name extension in EncryptedExtensions is typically empty
            // It just confirms that SNI was processed
            $this->context->setServerNameAcknowledged(true);
        }
    }

    private function parseALPNExtension(EncryptedExtensions $message): void
    {
        /** @var ALPNExtension $ext */
        $ext = $message->getExtension(ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
        if ($ext) {
            $protocols = $ext->getProtocols();

            // Server must select exactly one protocol
            if (count($protocols) !== 1) {
                throw new ProtocolViolationException(
                    "Server ALPN response must contain exactly one protocol, got " . count($protocols)
                );
            }

            $selectedProtocol = $protocols[0];

            // Verify server selected from our offered protocols
            $clientOfferedProtocols = $this->context->getClientOfferedProtocols();
            if (!in_array($selectedProtocol, $clientOfferedProtocols)) {
                throw new ProtocolViolationException(
                    "Server selected protocol '{$selectedProtocol}' not offered by client"
                );
            }

            $this->context->setSelectedProtocol($selectedProtocol);
        }
    }

    private function parseSupportedGroupsExtension(EncryptedExtensions $message): void
    {
        /** @var SupportedGroupsExtension $ext */
        $ext = $message->getExtension(ExtensionType::SUPPORTED_GROUPS);
        if ($ext) {
            // Server can send supported_groups in EncryptedExtensions
            // This is informational - tells client what groups server supports
            // for future connections or post-handshake auth
            $serverSupportedGroups = $ext->getGroups();
            $this->context->setServerSupportedGroups($serverSupportedGroups);
        }
    }
}
