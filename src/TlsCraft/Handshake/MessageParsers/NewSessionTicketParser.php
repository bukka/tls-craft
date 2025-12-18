<?php

namespace Php\TlsCraft\Handshake\MessageParsers;

use Php\TlsCraft\Handshake\Messages\NewSessionTicketMessage;

class NewSessionTicketParser extends AbstractMessageParser
{
    public function parse(string $data, int &$offset = 0): NewSessionTicketMessage
    {
        // Skip handshake header (type + length = 4 bytes)
        $offset += 4;

        // Ticket lifetime (4 bytes)
        $ticketLifetime = unpack('N', substr($data, $offset, 4))[1];
        $offset += 4;

        // Ticket age add (4 bytes)
        $ticketAgeAdd = unpack('N', substr($data, $offset, 4))[1];
        $offset += 4;

        // Ticket nonce length (1 byte)
        $nonceLength = unpack('C', substr($data, $offset, 1))[1];
        ++$offset;

        // Ticket nonce
        $ticketNonce = substr($data, $offset, $nonceLength);
        $offset += $nonceLength;

        // Ticket length (2 bytes)
        $ticketLength = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;

        // Ticket
        $ticket = substr($data, $offset, $ticketLength);
        $offset += $ticketLength;

        // Extensions
        $extensions = $this->extensionFactory->decodeExtensionList($data, $offset);

        return new NewSessionTicketMessage(
            ticketLifetime: $ticketLifetime,
            ticketAgeAdd: $ticketAgeAdd,
            ticketNonce: $ticketNonce,
            ticket: $ticket,
            extensions: $extensions,
        );
    }
}
