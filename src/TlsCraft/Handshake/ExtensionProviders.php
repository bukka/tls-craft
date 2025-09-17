<?php

namespace Php\TlsCraft\Extensions;

use Php\TlsCraft\Context;
use Php\TlsCraft\Messages\Providers\ExtensionProvider;

abstract class ExtensionProviders
{
    /** @var ExtensionProvider[] */
    protected array $providers = [];

    /** @param ExtensionProvider[] $providers */
    public function set(array $providers): void
    {
        $this->providers = [];
        foreach ($providers as $provider) {
            $this->add($provider);
        }
    }

    public function add(ExtensionProvider $provider): void
    {
        $this->providers[] = $provider;
    }

    public function addMany(array $providers): void
    {
        foreach ($providers as $provider) {
            $this->add($provider);
        }
    }

    public function insert(int $position, ExtensionProvider $provider): void
    {
        array_splice($this->providers, $position, 0, [$provider]);
    }

    public function clear(): void
    {
        $this->providers = [];
    }

    public function remove(int $extensionType): void
    {
        $this->providers = array_filter(
            $this->providers,
            fn($provider) => $provider->getExtensionType() !== $extensionType
        );
        $this->providers = array_values($this->providers); // Re-index
    }

    public function createExtensions(Context $context): array
    {
        $extensions = [];
        foreach ($this->providers as $provider) {
            $extension = $provider->create($context);
            if ($extension !== null) {
                $extensions[] = $extension;
            }
        }
        return $extensions;
    }

    public function getProviders(): array
    {
        return $this->providers;
    }
}