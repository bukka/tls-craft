<?php

namespace Php\TlsCraft\Messages\Providers;

use Php\TlsCraft\Context;
use Php\TlsCraft\Extensions\Extension;

class SniExtensionProvider implements ExtensionProvider
{
    public function __construct(
        private string $hostname
    )
    {
    }

    public function create(Context $context): ?Extension
    {
        // Only include SNI in ClientHello
        if (!$context->isClient()) {
            return null;
        }

        $sniData = pack('n', strlen($this->hostname) + 5) . // server_name_list length
            "\x00" . // name_type (host_name)
            pack('n', strlen($this->hostname)) . // hostname length
            $this->hostname;

        return new Extension(0, $sniData); // SNI extension type = 0
    }

    public function getExtensionType(): int
    {
        return 0;
    }
}