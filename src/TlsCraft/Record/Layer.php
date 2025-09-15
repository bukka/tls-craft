<?php

namespace Php\TlsCraft\Record;

use Php\TlsCraft\Connection\Connection;

class Layer
{
    private array $sendQueue = [];
    private bool $fragmentationEnabled = false;
    private int $maxFragmentSize = Record::MAX_PAYLOAD_LENGTH;

    public function __construct(
        private Connection         $connection,
        private ?RecordInterceptor $interceptor = null
    )
    {
    }

    public function setInterceptor(?RecordInterceptor $interceptor): void
    {
        $this->interceptor = $interceptor;
    }

    public function enableFragmentation(int $maxSize): void
    {
        $this->fragmentationEnabled = true;
        $this->maxFragmentSize = min($maxSize, Record::MAX_PAYLOAD_LENGTH);
    }

    public function disableFragmentation(): void
    {
        $this->fragmentationEnabled = false;
        $this->maxFragmentSize = Record::MAX_PAYLOAD_LENGTH;
    }

    public function sendRecord(Record $record): void
    {
        // Apply interception
        if ($this->interceptor) {
            if ($this->interceptor->shouldDrop($record)) {
                return;
            }

            $delay = $this->interceptor->getDelay($record);
            if ($delay > 0) {
                usleep((int)($delay * 1_000_000));
            }

            $record = $this->interceptor->beforeSend($record);

            $fragmentSize = $this->interceptor->shouldFragment($record);
            if ($fragmentSize !== null) {
                $this->sendFragmented($record, $fragmentSize);
                return;
            }
        }

        // Apply global fragmentation
        if ($this->fragmentationEnabled && $record->getLength() > $this->maxFragmentSize) {
            $this->sendFragmented($record, $this->maxFragmentSize);
            return;
        }

        $this->writeToSocket($record->serialize());
    }

    public function receiveRecord(): ?Record
    {
        $header = $this->readFromSocket(Record::HEADER_LENGTH);
        if ($header === null || strlen($header) < Record::HEADER_LENGTH) {
            return null;
        }

        $length = unpack('n', substr($header, 3, 2))[1];
        $payload = $this->readFromSocket($length);

        if ($payload === null || strlen($payload) < $length) {
            return null;
        }

        $recordData = $header . $payload;
        $offset = 0;
        $record = Record::parse($recordData, $offset);

        // Apply interception
        if ($this->interceptor) {
            $record = $this->interceptor->afterReceive($record);
        }

        return $record;
    }

    private function sendFragmented(Record $record, int $fragmentSize): void
    {
        $fragments = $record->fragment($fragmentSize);
        foreach ($fragments as $fragment) {
            $this->writeToSocket($fragment->serialize());
        }
    }

    private function writeToSocket(string $data): void
    {
        $written = 0;
        $length = strlen($data);

        while ($written < $length) {
            $result = $this->connection->write(substr($data, $written));
            $written += $result;
        }
    }

    private function readFromSocket(int $length): ?string
    {
        $data = '';
        $remaining = $length;

        while ($remaining > 0) {
            $chunk = $this->connection->read($remaining);
            if ($chunk === false || $chunk === '') {
                return null;
            }
            $data .= $chunk;
            $remaining -= strlen($chunk);
        }

        return $data;
    }
}