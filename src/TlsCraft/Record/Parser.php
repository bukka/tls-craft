<?php

namespace Php\TlsCraft\Record;

use Php\TlsCraft\Exceptions\CraftException;

class Parser
{
    public static function extractRecords(string $rawData): array
    {
        $records = [];
        $offset = 0;
        $dataLength = strlen($rawData);

        while ($offset < $dataLength) {
            try {
                $record = Record::parse($rawData, $offset);
                $records[] = $record;
            } catch (CraftException $e) {
                // If we can't parse more records, break
                break;
            }
        }

        return $records;
    }

    public static function findRecordBoundaries(string $rawData): array
    {
        $boundaries = [];
        $offset = 0;
        $dataLength = strlen($rawData);

        while ($offset < $dataLength) {
            if ($offset + Record::HEADER_LENGTH > $dataLength) {
                break;
            }

            $length = unpack('n', substr($rawData, $offset + 3, 2))[1];
            $recordEnd = $offset + Record::HEADER_LENGTH + $length;

            $boundaries[] = [
                'start' => $offset,
                'end' => $recordEnd,
                'length' => $length,
            ];

            $offset = $recordEnd;
        }

        return $boundaries;
    }
}
