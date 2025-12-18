<?php

namespace Php\TlsCraft\Handshake\MessageSerializers;

use Php\TlsCraft\Handshake\Messages\NewSessionTicketMessage;

class NewSessionTicketSerializer extends AbstractMessageSerializer
{
    public function serialize(NewSessionTicketMessage $message): string
    {
        $encoded = '';

        // Ticket lifetime (4 bytes)
        $encoded .= pack('N', $message->ticketLifetime);

        // Ticket age add (4 bytes)
        $encoded .= pack('N', $message->ticketAgeAdd);

        // Ticket nonce length + nonce
        $encoded .= pack('C', strlen($message->ticketNonce));
        $encoded .= $message->ticketNonce;

        // Ticket length + ticket
        $encoded .= pack('n', strlen($message->ticket));
        $encoded .= $message->ticket;

        // Extensions
        $encoded .= $this->extensionFactory->encodeExtensionList($message->extensions);

        return $encoded;
    }
}
