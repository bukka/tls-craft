<?php

namespace Php\TlsCraft\Handshake;

use Php\TlsCraft\Context;
use Php\TlsCraft\Exceptions\CraftException;
use Php\TlsCraft\Handshake\Messages\CertificateMessage;
use Php\TlsCraft\Handshake\Messages\CertificateRequestMessage;
use Php\TlsCraft\Handshake\Messages\CertificateVerifyMessage;
use Php\TlsCraft\Handshake\Messages\ClientHelloMessage;
use Php\TlsCraft\Handshake\Messages\EncryptedExtensionsMessage;
use Php\TlsCraft\Handshake\Messages\EndOfEarlyDataMessage;
use Php\TlsCraft\Handshake\Messages\FinishedMessage;
use Php\TlsCraft\Handshake\Messages\KeyUpdateMessage;
use Php\TlsCraft\Handshake\Messages\Message;
use Php\TlsCraft\Handshake\Messages\NewSessionTicketMessage;
use Php\TlsCraft\Handshake\Messages\ServerHelloMessage;
use Php\TlsCraft\Handshake\MessageSerializers\CertificateRequestSerializer;
use Php\TlsCraft\Handshake\MessageSerializers\CertificateSerializer;
use Php\TlsCraft\Handshake\MessageSerializers\CertificateVerifySerializer;
use Php\TlsCraft\Handshake\MessageSerializers\ClientHelloSerializer;
use Php\TlsCraft\Handshake\MessageSerializers\EncryptedExtensionsSerializer;
use Php\TlsCraft\Handshake\MessageSerializers\EndOfEarlyDataSerializer;
use Php\TlsCraft\Handshake\MessageSerializers\FinishedSerializer;
use Php\TlsCraft\Handshake\MessageSerializers\KeyUpdateSerializer;
use Php\TlsCraft\Handshake\MessageSerializers\NewSessionTicketSerializer;
use Php\TlsCraft\Handshake\MessageSerializers\ServerHelloSerializer;
use Php\TlsCraft\Logger;

/**
 * Serialize messages to bytes.
 */
class MessageSerializer
{
    private ?ClientHelloSerializer $clientHelloSerializer = null;
    private ?ServerHelloSerializer $serverHelloSerializer = null;
    private ?EncryptedExtensionsSerializer $encryptedExtensionsSerializer = null;
    private ?CertificateSerializer $certificateSerializer = null;
    private ?CertificateRequestSerializer $certificateRequestSerializer = null;
    private ?CertificateVerifySerializer $certificateVerifySerializer = null;
    private ?FinishedSerializer $finishedSerializer = null;
    private ?KeyUpdateSerializer $keyUpdateSerializer = null;
    private ?NewSessionTicketSerializer $newSessionTicketSerializer = null;
    private ?EndOfEarlyDataSerializer $endOfEarlyDataSerializer = null;

    public function __construct(
        private readonly Context $context,
        private readonly ExtensionFactory $extensionFactory,
    ) {
    }

    private function getClientHelloSerializer(): ClientHelloSerializer
    {
        return $this->clientHelloSerializer ??= new ClientHelloSerializer($this->context, $this->extensionFactory);
    }

    private function getServerHelloSerializer(): ServerHelloSerializer
    {
        return $this->serverHelloSerializer ??= new ServerHelloSerializer($this->context, $this->extensionFactory);
    }

    private function getEncryptedExtensionsSerializer(): EncryptedExtensionsSerializer
    {
        return $this->encryptedExtensionsSerializer ??= new EncryptedExtensionsSerializer($this->context, $this->extensionFactory);
    }

    private function getCertificateSerializer(): CertificateSerializer
    {
        return $this->certificateSerializer ??= new CertificateSerializer($this->context, $this->extensionFactory);
    }

    private function getCertificateRequestSerializer(): CertificateRequestSerializer
    {
        return $this->certificateRequestSerializer ??= new CertificateRequestSerializer($this->context, $this->extensionFactory);
    }

    private function getCertificateVerifySerializer(): CertificateVerifySerializer
    {
        return $this->certificateVerifySerializer ??= new CertificateVerifySerializer($this->context, $this->extensionFactory);
    }

    private function getFinishedSerializer(): FinishedSerializer
    {
        return $this->finishedSerializer ??= new FinishedSerializer($this->context, $this->extensionFactory);
    }

    private function getKeyUpdateSerializer(): KeyUpdateSerializer
    {
        return $this->keyUpdateSerializer ??= new KeyUpdateSerializer($this->context, $this->extensionFactory);
    }

    private function getNewSessionTicketSerializer(): NewSessionTicketSerializer
    {
        return $this->newSessionTicketSerializer ??= new NewSessionTicketSerializer($this->context, $this->extensionFactory);
    }

    private function getEndOfEarlyDataSerializer(): EndOfEarlyDataSerializer
    {
        return $this->endOfEarlyDataSerializer ??= new EndOfEarlyDataSerializer($this->context, $this->extensionFactory);
    }

    /**
     * Call serialize based on a message type.
     */
    private function serializeMessage(Message $message): string
    {
        return match (true) {
            $message instanceof ClientHelloMessage => $this->getClientHelloSerializer()->serialize($message),
            $message instanceof ServerHelloMessage => $this->getServerHelloSerializer()->serialize($message),
            $message instanceof EncryptedExtensionsMessage => $this->getEncryptedExtensionsSerializer()->serialize($message),
            $message instanceof CertificateMessage => $this->getCertificateSerializer()->serialize($message),
            $message instanceof CertificateRequestMessage => $this->getCertificateRequestSerializer()->serialize($message),
            $message instanceof CertificateVerifyMessage => $this->getCertificateVerifySerializer()->serialize($message),
            $message instanceof FinishedMessage => $this->getFinishedSerializer()->serialize($message),
            $message instanceof KeyUpdateMessage => $this->getKeyUpdateSerializer()->serialize($message),
            $message instanceof NewSessionTicketMessage => $this->getNewSessionTicketSerializer()->serialize($message),
            $message instanceof EndOfEarlyDataMessage => $this->getEndOfEarlyDataSerializer()->serialize($message),
            default => throw new CraftException('No serializer available for message type: '.$message::class),
        };
    }

    /**
     * Serialize with a handshake header.
     */
    public function serialize(Message $message): string
    {
        $payload = $this->serializeMessage($message);

        $len = strlen($payload);
        if ($len > 0xFFFFFF) {
            throw new CraftException('Handshake message too large');
        }

        // 3-byte length: take the last 3 bytes of the 4-byte BE int
        $len3 = substr(pack('N', $len), 1);

        $data = $message->type->toByte().$len3.$payload;

        Logger::debug('Serialize Message', [
            'type' => $message->type->name,
            'data' => $data,
        ]);

        return $data;
    }
}
