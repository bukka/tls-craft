<?php

namespace Php\TlsCraft\Handshake;

use Php\TlsCraft\Context;
use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Handshake\MessageSerializers\{
    CertificateSerializer,
    CertificateVerifySerializer,
    ClientHelloSerializer,
    EncryptedExtensionsSerializer,
    FinishedSerializer,
    KeyUpdateSerializer,
    ServerHelloSerializer
};
use Php\TlsCraft\Handshake\Messages\{
    Message,
    Certificate,
    CertificateVerify,
    ClientHello,
    EncryptedExtensions,
    Finished,
    KeyUpdate,
    ServerHello
};
use Php\TlsCraft\Logger;

/**
 * Serialize messages to bytes.
 */
class MessageSerializer
{
    public function __construct(
        private Context $context,
        private ExtensionFactory $extensionFactory,
    ) {}

    /** --------- Cached serializer instances ---------- */
    private ?ClientHelloSerializer $clientHelloSerializer = null;
    private ?ServerHelloSerializer $serverHelloSerializer = null;
    private ?EncryptedExtensionsSerializer $encryptedExtensionsSerializer = null;
    private ?CertificateSerializer $certificateSerializer = null;
    private ?CertificateVerifySerializer $certificateVerifySerializer = null;
    private ?FinishedSerializer $finishedSerializer = null;
    private ?KeyUpdateSerializer $keyUpdateSerializer = null;

    private function getClientHelloSerializer(): ClientHelloSerializer
    {
        return $this->clientHelloSerializer ??=
            new ClientHelloSerializer($this->context, $this->extensionFactory);
    }

    private function getServerHelloSerializer(): ServerHelloSerializer
    {
        return $this->serverHelloSerializer ??=
            new ServerHelloSerializer($this->context, $this->extensionFactory);
    }

    private function getEncryptedExtensionsSerializer(): EncryptedExtensionsSerializer
    {
        return $this->encryptedExtensionsSerializer ??=
            new EncryptedExtensionsSerializer($this->context, $this->extensionFactory);
    }

    private function getCertificateSerializer(): CertificateSerializer
    {
        return $this->certificateSerializer ??=
            new CertificateSerializer($this->context, $this->extensionFactory);
    }

    private function getCertificateVerifySerializer(): CertificateVerifySerializer
    {
        return $this->certificateVerifySerializer ??=
            new CertificateVerifySerializer($this->context, $this->extensionFactory);
    }

    private function getFinishedSerializer(): FinishedSerializer
    {
        return $this->finishedSerializer ??=
            new FinishedSerializer($this->context, $this->extensionFactory);
    }

    private function getKeyUpdateSerializer(): KeyUpdateSerializer
    {
        return $this->keyUpdateSerializer ??=
            new KeyUpdateSerializer($this->context, $this->extensionFactory);
    }

    /**
     * Call serialize based on a message type.
     */
    private function serializeMessage(Message $msg): string
    {
        return match (true) {
            $msg instanceof ClientHello        => $this->getClientHelloSerializer()->serialize($msg),
            $msg instanceof ServerHello        => $this->getServerHelloSerializer()->serialize($msg),
            $msg instanceof EncryptedExtensions=> $this->getEncryptedExtensionsSerializer()->serialize($msg),
            $msg instanceof Certificate        => $this->getCertificateSerializer()->serialize($msg),
            $msg instanceof CertificateVerify  => $this->getCertificateVerifySerializer()->serialize($msg),
            $msg instanceof Finished           => $this->getFinishedSerializer()->serialize($msg),
            $msg instanceof KeyUpdate          => $this->getKeyUpdateSerializer()->serialize($msg),
            default => throw new CraftException('No serializer for message: ' . $msg::class),
        };
    }

    /**
     * Serialize with a handshake header.
     */
    public function serialize(Message $msg): string
    {
        $payload = $this->serializeMessage($msg);

        $len = strlen($payload);
        if ($len > 0xFFFFFF) {
            throw new CraftException('Handshake message too large');
        }

        // 3-byte length: take the last 3 bytes of the 4-byte BE int
        $len3 = substr(pack('N', $len), 1);

        $data = $msg->type->toByte() . $len3 . $payload;

        Logger::debug('Serialize Message', [
            'type' => $msg->type->name,
            'data' => $data,
        ]);

        return $data;
    }
}
