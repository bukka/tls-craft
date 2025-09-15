<?php

namespace Php\TlsCraft\Extensions\Providers;

use Php\TlsCraft\Context;
use Php\TlsCraft\Extensions\Extension;

class SupportedVersionsProvider implements ExtensionProvider
{
    public function __construct(
        private array $supportedVersions
    )
    {
    }

    public function create(Context $context): ?Extension
    {
        if ($context->isClient()) {
            // ClientHello: supported_versions_list
            $data = chr(count($this->supportedVersions) * 2); // length
            foreach ($this->supportedVersions as $version) {
                $data .= $version->toBytes();
            }
        } else {
            // ServerHello: selected_version
            $negotiatedVersion = $context->getNegotiatedVersion();
            $data = $negotiatedVersion->toBytes();
        }

        return new Extension($this->getExtensionType(), $data); // supported_versions = 43
    }

    public function getExtensionType(): int
    {
        return 43;
    }
}