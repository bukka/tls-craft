<?php

namespace Php\TlsCraft\Handshake\MessageSerializers;

use Php\TlsCraft\Handshake\Messages\ClientHello;

class ClientHelloSerializer extends AbstractMessageSerializer
{
    public function serialize(ClientHello $message): string
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
