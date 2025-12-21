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
        $pskExtension = $message->getExtension(ExtensionType::PRE_SHARED_KEY);

        if (!($pskExtension instanceof PreSharedKeyExtension)) {
            return $this->serializeInternal($message);
        }

        if ($pskExtension->hasBinders()) {
            return $this->serializeInternal($message);
        }

        return $this->serializeWithBinderCalculation($message, $pskExtension);
    }

    private function serializeWithBinderCalculation(
        ClientHelloMessage $message,
        PreSharedKeyExtension $pskExtension,
    ): string {
        // FIRST PASS: Serialize with zero binders
        $fullData = $this->serializeInternal($message);
        $fullLength = strlen($fullData);

        // Get binder length from PSK cipher suite
        $binderLength = $pskExtension->getBinderLength($this->context->getOfferedPsks());

        // Strip binders
        $bindersLength = $pskExtension->getBindersLength($binderLength);
        $partialData = substr($fullData, 0, -$bindersLength);

        Logger::debug('First pass serialization complete (with zero binders)', [
            'full_length' => $fullLength,
            'partial_data_length' => strlen($partialData),
            'binders_length' => $bindersLength,
        ]);

        // Add handshake message header
        $handshakeHeader = chr(0x01); // ClientHello type
        $handshakeHeader .= substr(pack('N', $fullLength), 1, 3); // 3-byte length

        $partialWithHeader = $handshakeHeader.$partialData;

        // Calculate binders
        $binders = $this->context->getPskBinderCalculator()->calculateBinders(
            $this->context->getOfferedPsks(),
            $partialWithHeader,
            '',
        );

        $pskExtension->setBinders($binders);

        Logger::debug('Binders calculated and set', [
            'binder_count' => count($binders),
        ]);

        // Second pass with real binders
        return $this->serializeInternal($message);
    }

    private function serializeInternal(ClientHelloMessage $message): string
    {
        $encoded = $message->version->toBytes();
        $encoded .= $message->random;
        $encoded .= chr(strlen($message->sessionId)).$message->sessionId;

        // Cipher suites
        $cipherSuitesData = '';
        foreach ($message->cipherSuites as $suite) {
            $cipherSuitesData .= pack('n', $suite);
        }
        $encoded .= pack('n', strlen($cipherSuitesData)).$cipherSuitesData;

        // Compression methods
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
