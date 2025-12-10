<?php

namespace Php\TlsCraft\Handshake\MessageSerializers;

use Php\TlsCraft\Handshake\Messages\Certificate;

class CertificateSerializer extends AbstractMessageSerializer
{
    public function serialize(Certificate $message): string
    {
        // Certificate request context (empty for server certificate)
        $contextLength = strlen($message->certificateRequestContext);
        $data = chr($contextLength) . $message->certificateRequestContext;

        // Certificate list
        $certListData = '';
        $certificates = $message->certificateChain->toDERArray();

        foreach ($certificates as $certDER) {
            $certLength = strlen($certDER);

            // 3-byte length prefix
            $certListData .= substr(pack('N', $certLength), 1);

            // Certificate DER data
            $certListData .= $certDER;

            // Extensions (empty for now)
            $certListData .= "\x00\x00";
        }

        // 3-byte length prefix for entire certificate list
        $data .= substr(pack('N', strlen($certListData)), 1);
        $data .= $certListData;

        return $data;
    }
}
