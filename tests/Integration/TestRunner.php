<?php

namespace Php\TlsCraft\Tests\Integration;

use Exception;

use const PHP_BINARY;
use const STDERR;
use const STDIN;

/**
 * Test runner for spawning client/server processes in integration tests
 * Allows PHPUnit tests to spawn subprocesses for multi-party TLS testing
 */
class TestRunner
{
    public const ROLE_CLIENT = 'client';
    public const ROLE_SERVER = 'server';
    public const WORKER_MARKER = 'TLS_INTEGRATION_WORKER';

    private array $workerProcesses = [];
    private array $workerPipes = [];
    private bool $isWorker = false;

    public function __construct(bool $isWorker = false)
    {
        $this->isWorker = $isWorker;
    }

    /**
     * Start a server in subprocess, return address when ready
     * Call this from your test, then run your client code
     *
     * @throws Exception If server process fails to start
     */
    public function startServerProcess(string $serverCode): string
    {
        $this->startWorker(self::ROLE_SERVER, $serverCode);

        $address = $this->waitForWorkerReady(self::ROLE_SERVER);
        if (!$address) {
            throw new Exception('Server process failed to start');
        }

        return trim($address);
    }

    /**
     * Start a client in subprocess, return immediately
     * Call this from your test, then run your server code
     * Pass server address to client code using {{ADDR}} placeholder
     */
    public function startClientProcess(string $clientCode, string $serverAddress): void
    {
        // Replace {{ADDR}} in client code
        $clientCode = str_replace('{{ADDR}}', $serverAddress, $clientCode);
        $this->startWorker(self::ROLE_CLIENT, $clientCode);
    }

    /**
     * Wait for subprocess to complete
     *
     * @return bool True if process completed successfully (exit code 0)
     */
    public function waitForCompletion(string $role, int $timeoutSeconds = 30): bool
    {
        if (!isset($this->workerProcesses[$role])) {
            return false;
        }

        $startTime = time();
        while (time() - $startTime < $timeoutSeconds) {
            $status = proc_get_status($this->workerProcesses[$role]);
            if (!$status['running']) {
                return $status['exitcode'] === 0;
            }
            usleep(100000); // 100ms
        }

        // Timeout - terminate process
        proc_terminate($this->workerProcesses[$role]);
        return false;
    }

    /**
     * Stop and cleanup worker process
     */
    public function stopWorker(string $role): void
    {
        if (isset($this->workerPipes[$role])) {
            @fclose($this->workerPipes[$role][0]);
            @fclose($this->workerPipes[$role][1]);
        }

        if (isset($this->workerProcesses[$role])) {
            proc_terminate($this->workerProcesses[$role]);
            proc_close($this->workerProcesses[$role]);
        }

        unset($this->workerPipes[$role], $this->workerProcesses[$role]);
    }

    /**
     * Cleanup all worker processes
     */
    public function cleanup(): void
    {
        foreach (array_keys($this->workerProcesses) as $role) {
            $this->stopWorker($role);
        }
    }

    /**
     * Send message from worker to main process
     */
    public function notifyMain(string $message): void
    {
        if ($this->isWorker) {
            echo $message . "\n";
            flush();
        }
    }

    /**
     * Notify that server is ready with address
     */
    public function notifyServerReady(string $address): void
    {
        $this->notifyMain('READY:' . $address);
    }

    /**
     * Notify client (from main process) that server is ready to accept connections
     */
    public function notifyClientReady(): void
    {
        if (isset($this->workerPipes[self::ROLE_CLIENT])) {
            fwrite($this->workerPipes[self::ROLE_CLIENT][0], "GO\n");
            fflush($this->workerPipes[self::ROLE_CLIENT][0]);
        }
    }

    /**
     * Wait for server notification (called from client worker subprocess)
     */
    public function waitForServerNotification(int $timeoutSeconds = 30): void
    {
        if (!$this->isWorker) {
            return;
        }

        $startTime = time();
        while (time() - $startTime < $timeoutSeconds) {
            stream_set_blocking(STDIN, false);
            $line = fgets(STDIN);
            if ($line !== false && trim($line) === 'GO') {
                return;
            }
            usleep(100000); // 100ms
        }

        die('Timeout waiting for server ready notification');
    }

    /**
     * Run worker process (internal use only)
     */
    public function runWorker(): void
    {
        if (!$this->isWorker) {
            return;
        }

        // Read code from stdin
        $code = '';
        while (($line = fgets(STDIN)) !== false) {
            if (trim($line) === '---END---') {
                break;
            }
            $code .= $line;
        }

        try {
            // Execute worker code
            eval($code);
        } catch (Exception $e) {
            echo 'WORKER_ERROR: ' . $e->getMessage() . "\n";
            echo $e->getTraceAsString() . "\n";
            exit(1);
        }
    }

    private function startWorker(string $role, string $code): void
    {
        $cmd = sprintf(
            '%s %s "%s" %s %s',
            PHP_BINARY,
            getenv('TEST_PHP_EXTRA_ARGS') ?: '',
            __FILE__,
            self::WORKER_MARKER,
            $role,
        );

        $pipes = [];
        $this->workerProcesses[$role] = proc_open(
            $cmd,
            [
                0 => ['pipe', 'r'], // stdin
                1 => ['pipe', 'w'], // stdout
                2 => STDERR,         // stderr (inherit for debugging)
            ],
            $pipes,
        );

        if (!$this->workerProcesses[$role]) {
            throw new Exception("Failed to start worker process for role: $role");
        }

        $this->workerPipes[$role] = $pipes;

        // Send code to worker
        fwrite($pipes[0], $this->stripPhpTags($code) . "\n---END---\n");
    }

    private function waitForWorkerReady(string $role, int $timeoutSeconds = 10): ?string
    {
        if (!isset($this->workerPipes[$role])) {
            return null;
        }

        $stdout = $this->workerPipes[$role][1];
        stream_set_blocking($stdout, false);

        $startTime = time();
        while (time() - $startTime < $timeoutSeconds) {
            $read = [$stdout];
            $write = $except = [];

            if (stream_select($read, $write, $except, 0, 100000)) {
                $line = fgets($stdout);
                if ($line !== false && str_starts_with($line, 'READY:')) {
                    return substr($line, 6); // Remove 'READY:' prefix
                }
            }
            usleep(50000); // 50ms
        }

        return null;
    }

    private function stripPhpTags(string $code): string
    {
        return preg_replace('/^\s*<\?(?:php)?\s*|\s*\?>\s*$/i', '', trim($code));
    }
}

// Auto-run worker if called with worker marker
if (isset($argv[1]) && $argv[1] === TestRunner::WORKER_MARKER) {
    (new TestRunner(true))->runWorker();
}
