<?php

namespace Php\TlsCraft\Handshake\Messages;

use Php\TlsCraft\Protocol\HandshakeType;

class Certificate extends Message
{
    public function __construct(
        public readonly string $certificateRequestContext,
        public readonly array $certificateList, // array of certificate entries
    ) {
        parent::__construct(HandshakeType::CERTIFICATE);
    }

    public function encode(): string
    {
        $encoded = chr(strlen($this->certificateRequestContext)).$this->certificateRequestContext;

        $certListData = '';
        foreach ($this->certificateList as $cert) {
            $certListData .= substr(pack('N', strlen($cert)), 1).$cert; // 3-byte length + cert
            $certListData .= "\x00\x00"; // Empty extensions
        }

        $encoded .= substr(pack('N', strlen($certListData)), 1).$certListData;

        return $encoded;
    }
}
