<?php

namespace Php\TlsCraft\Session;

/**
 * Plain JSON session ticket serializer (for testing/development)
 */
class PlainSessionTicketSerializer extends AbstractSessionTicketSerializer
{
    public function serialize(SessionTicketData $data): string
    {
        return $this->encodeToJson($data);
    }

    public function unserialize(string $ticket): ?SessionTicketData
    {
        return $this->decodeFromJson($ticket);
    }
}
