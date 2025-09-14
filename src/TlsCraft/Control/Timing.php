<?php

namespace Php\TlsCraft\Control;

use Php\TlsCraft\Protocol\ContentType;
use Php\TlsCraft\State\ConnectionState;

class Timing
{
    private array $recordDelays = [];
    private array $stateDelays = [];
    private float $globalDelay = 0.0;
    private bool $randomJitterEnabled = false;
    private float $maxJitter = 0.0;

    public function addRecordDelay(ContentType $type, float $seconds): self
    {
        $this->recordDelays[$type->value] = $seconds;
        return $this;
    }

    public function addStateDelay(ConnectionState $state, float $seconds): self
    {
        $this->stateDelays[$state->value] = $seconds;
        return $this;
    }

    public function setGlobalDelay(float $seconds): self
    {
        $this->globalDelay = $seconds;
        return $this;
    }

    public function enableJitter(float $maxJitter): self
    {
        $this->randomJitterEnabled = true;
        $this->maxJitter = $maxJitter;
        return $this;
    }

    public function getRecordDelay(ContentType $type): float
    {
        $delay = $this->recordDelays[$type->value] ?? 0.0;
        $delay += $this->globalDelay;

        if ($this->randomJitterEnabled) {
            $delay += mt_rand(0, (int)($this->maxJitter * 1000)) / 1000;
        }

        return $delay;
    }

    public function getStateDelay(ConnectionState $state): float
    {
        return $this->stateDelays[$state->value] ?? 0.0;
    }

    public function applyDelay(float $seconds): void
    {
        if ($seconds > 0) {
            usleep((int)($seconds * 1_000_000));
        }
    }
}