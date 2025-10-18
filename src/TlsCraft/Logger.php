<?php

namespace Php\TlsCraft;

/**
 * Minimal, dependency-free debug logger.
 * Usage:
 *   Logger::enable('/tmp/tls-craft.log');  // or Logger::enable(); to log to stderr
 *   Logger::debug('HKDF-Extract', ['Algorithm' => 'sha256', 'PRK' => $binary]);
 */
final class Logger
{
    public const DEBUG = 'DEBUG';
    public const INFO  = 'INFO';
    public const WARN  = 'WARN';
    public const ERROR = 'ERROR';

    private static bool $enabled = false;
    private static ?string $file = null;
    private static string $minLevel = self::DEBUG; // simple gate

    public static function enable(?string $file = null, string $minLevel = self::DEBUG): void
    {
        self::$enabled = true;
        self::$file = $file;
        self::$minLevel = $minLevel;
    }

    public static function disable(): void
    {
        self::$enabled = false;
    }

    public static function isEnabled(): bool
    {
        return self::$enabled;
    }

    public static function debug(string $title, array|string|null $data = null): void
    {
        self::log(self::DEBUG, $title, $data);
    }
    public static function info(string $title, array|string|null $data = null): void
    {
        self::log(self::INFO, $title, $data);
    }
    public static function warn(string $title, array|string|null $data = null): void
    {
        self::log(self::WARN, $title, $data);
    }
    public static function error(string $title, array|string|null $data = null): void
    {
        self::log(self::ERROR, $title, $data);
    }

    /** Auto-hex binary values; keep ASCII as-is */
    private static function normalizeValue(mixed $v): string
    {
        if (is_string($v)) {
            // Heuristic: if contains non-printable, treat as binary
            if ($v === '' || preg_match('/[^\x20-\x7E]/', $v)) {
                return bin2hex($v);
            }
            return $v;
        }
        if (is_bool($v)) return $v ? 'true' : 'false';
        if (is_null($v)) return 'null';
        if (is_scalar($v)) return (string)$v;
        return json_encode($v, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
    }

    private static function levelRank(string $level): int
    {
        return match ($level) {
            self::DEBUG => 0,
            self::INFO  => 1,
            self::WARN  => 2,
            self::ERROR => 3,
            default => 0,
        };
    }

    private static function log(string $level, string $title, array|string|null $data): void
    {
        if (!self::$enabled) return;
        if (self::levelRank($level) < self::levelRank(self::$minLevel)) return;

        $time = date('Y-m-d H:i:s');
        $out  = "[{$time} {$level}] {$title}";

        if (is_array($data)) {
            foreach ($data as $k => $v) {
                $out .= "\n  {$k}: " . self::normalizeValue($v);
            }
        } elseif (is_string($data) && $data !== '') {
            $out .= "\n  " . self::normalizeValue($data);
        }

        $out .= "\n";

        if (self::$file) {
            @file_put_contents(self::$file, $out, FILE_APPEND);
        } else {
            @file_put_contents('php://stderr', $out);
        }
    }
}
