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
        $partialData = $this->serializeInternal($message);

        // Strip binders from extension
        // Structure: [2 bytes: binders length] + [1 byte: binder1 len] + [binder1] + ...
        $binderLength = $pskExtension->getBinderLength($this->context->getOfferedPsks());
        $singleBinderSize = 1 + $binderLength; // 1-byte length prefix + binder data
        $bindersLength = 2 + ($pskExtension->getIdentityCount() * $singleBinderSize);

        $partialData = substr($partialData, 0, -$bindersLength);

        Logger::debug('First pass serialization complete (with zero binders)', [
            'partial_data_length' => strlen($partialData),
            'partial_data' => $partialData,
        ]);

        // Calculate binders based on partial ClientHello
        $binders = $this->context->getPskBinderCalculator()->calculateBinders(
            $this->context->getOfferedPsks(),
            $partialData,
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
            'final_data' => $finalData,
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
