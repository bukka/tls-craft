<?php

namespace Php\TlsCraft\Extensions\Providers;

use Php\TlsCraft\Context;
use Php\TlsCraft\Extensions\Extension;

class AlpnExtensionProvider implements ExtensionProvider
{
    public function __construct(
        private array $protocols
    ) {}

    public function create(Context $context): ?Extension
    {
        if ($context->isClient()) {
            return $this->createClientALPN();
        } else {
            return $this->createServerALPN($context);
        }
    }

    public function getExtensionType(): int
    {
        return 16;
    }

    private function createClientALPN(): Extension
    {
        $protocolList = '';
        foreach ($this->protocols as $protocol) {
            $protocolList .= chr(strlen($protocol)) . $protocol;
        }

        $data = pack('n', strlen($protocolList)) . $protocolList;

        return new Extension(16, $data);
    }

    private function createServerALPN(Context $context): ?Extension
    {
        // Server responds with the selected protocol
        // For now, just select the first one
        $selectedProtocol = $this->protocols[0] ?? null;

        if ($selectedProtocol === null) {
            return null;
        }

        $data = pack('n', strlen($selectedProtocol) + 1) . // protocol_name_list length
            chr(strlen($selectedProtocol)) . // protocol length
            $selectedProtocol;

        return new Extension(16, $data);
    }
}