<?php

namespace Php\TlsCraft\Handshake\MessageSerializers;

use Php\TlsCraft\Handshake\Extensions\PreSharedKeyExtension;
use Php\TlsCraft\Handshake\ExtensionType;
use Php\TlsCraft\Handshake\Messages\ClientHelloMessage;
use Php\TlsCraft\Logger;

class ClientHelloSerializer extends AbstractMessageSerializer
{
    public function serialize(ClientHelloMessage $message): string
    {
        // Check if message has PSK extension
        $pskExtension = $message->getExtension(ExtensionType::PRE_SHARED_KEY);

        if (!($pskExtension instanceof PreSharedKeyExtension)) {
            // No PSK extension - normal serialization
            return $this->serializeInternal($message);
        }

        if ($pskExtension->hasBinders()) {
            // Binders already set (e.g., re-serializing parsed message) - normal serialization
            return $this->serializeInternal($message);
        }

        // Two-pass serialization for PSK with binder calculation
        return $this->serializeWithBinderCalculation($message, $pskExtension);
    }

    /**
     * Two-pass serialization with PSK binder calculation
     */
    private function serializeWithBinderCalculation(
        ClientHelloMessage $message,
        PreSharedKeyExtension $pskExtension,
    ): string {
        // FIRST PASS: Serialize with zero binders
        $fullData = $this->serializeInternal($message);
        $fullLength = strlen($fullData);

        // Strip binders from extension
        $binderLength = $pskExtension->getBinderLength($this->context->getOfferedPsks());
        $singleBinderSize = 1 + $binderLength;
        $bindersLength = 2 + ($pskExtension->getIdentityCount() * $singleBinderSize);

        $partialData = substr($fullData, 0, -$bindersLength);

        Logger::debug('First pass serialization complete (with zero binders)', [
            'full_length' => $fullLength,
            'partial_data_length' => strlen($partialData),
            'partial_data' => bin2hex($partialData),
        ]);

        // Add handshake message header for binder calculation
        // Format: Type (1 byte) + Length (3 bytes) + Body
        // Length is the FULL body length (including zero binders that will be replaced)
        $handshakeHeader = chr(0x01); // ClientHello type
        $handshakeHeader .= substr(pack('N', $fullLength), 1, 3); // 3-byte length (big-endian)

        $partialWithHeader = $handshakeHeader.$partialData;

        Logger::debug('Partial ClientHello with handshake header', [
            'total_length' => strlen($partialWithHeader),
            'header' => bin2hex($handshakeHeader),
            'header_length_field' => $fullLength,
        ]);

        // Calculate binders based on partial ClientHello WITH header
        $binders = $this->context->getPskBinderCalculator()->calculateBinders(
            $this->context->getOfferedPsks(),
            $partialWithHeader,
            '', // No previous transcript for initial ClientHello
        );

        // Set calculated binders in extension
        $pskExtension->setBinders($binders);

        Logger::debug('Binders calculated and set', [
            'binder_count' => count($binders),
        ]);

        // Second pass - serialize with real binders
        $finalData = $this->serializeInternal($message);

        Logger::debug('Second pass serialization complete (with real binders)', [
            'final_data_length' => strlen($finalData),
            'final_data' => bin2hex($finalData),
        ]);

        return $finalData;
    }

    /**
     * Internal serialization method
     */
    private function serializeInternal(ClientHelloMessage $message): string
    {
        $encoded = $message->version->toBytes();
        $encoded .= $message->random;

        // Session ID (length-prefixed)
        $encoded .= chr(strlen($message->sessionId)).$message->sessionId;

        // Cipher suites (length-prefixed, 2 bytes per suite)
        $cipherSuitesData = '';
        foreach ($message->cipherSuites as $suite) {
            $cipherSuitesData .= pack('n', $suite);
        }
        $encoded .= pack('n', strlen($cipherSuitesData)).$cipherSuitesData;

        // Compression methods (length-prefixed, 1 byte per method)
        $compressionData = '';
        foreach ($message->compressionMethods as $method) {
            $compressionData .= chr($method);
        }
        $encoded .= chr(strlen($compressionData)).$compressionData;

        // Extensions
        $encoded .= $this->extensionFactory->encodeExtensionList($message->extensions);

        return $encoded;
    }
}
