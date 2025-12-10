<?php

namespace Php\TlsCraft\Handshake\MessageSerializers;

use Php\TlsCraft\Handshake\Messages\ServerHelloMessage;

class ServerHelloSerializer extends AbstractMessageSerializer
{
    public function serialize(ServerHelloMessage $message): string
    {
        $encoded = $message->version->toBytes();
        $encoded .= $message->random;

        // Session ID (length-prefixed)
        $encoded .= chr(strlen($message->sessionId)).$message->sessionId;

        // Cipher suite (2 bytes)
        $encoded .= pack('n', $message->cipherSuite->value);

        // Compression method (1 byte)
        $encoded .= chr($message->compressionMethod);

        // Extensions
        $encoded .= $this->extensionFactory->encodeExtensionList($message->extensions);

        return $encoded;
    }
}
