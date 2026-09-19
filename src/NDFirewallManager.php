<?php

namespace NDFirewall;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use NDFirewall\Engine\RuleSet;
use NDFirewall\Engine\Scanner;
use NDFirewall\Engine\ScanResult;
use Throwable;

/**
 * The single entry point developers talk to (also bound behind the
 * NDFirewall facade). Every public method here is safe to call from
 * anywhere in application code and is guaranteed to never throw —
 * see the try/catch wrapping in scanRequest()/scan().
 */
class NDFirewallManager
{
    public function __construct(private readonly array $config)
    {
    }

    /**
     * Scan a full request against the configured default targets.
     * This never throws; on internal error it returns a clean/failed
     * ScanResult and the caller (middleware) decides what to do based on
     * config('ndfirewall.on_internal_error').
     */
    public function scanRequest(Request $request, ?array $targets = null): ScanResult
    {
        try {
            $targets ??= $this->config['default_targets'] ?? ['query', 'post', 'cookies', 'path'];

            $inputs = [];
            foreach ($targets as $target) {
                $inputs[$target] = $this->extractTarget($request, $target);
            }

            $rules = RuleSet::active($this->config['categories'] ?? []);

            $scanner = $this->scanner();
            $result = $scanner->scan($inputs, $rules);

            $this->log($result, $request);

            return $result;
        } catch (Throwable $e) {
            $this->logRaw('ndfirewall engine error during scanRequest: '.$e->getMessage());

            return ScanResult::engineFailed($e->getMessage());
        }
    }

    /**
     * Scan a single arbitrary value — for developers who want to guard one
     * function/argument directly instead of (or in addition to) a route
     * middleware. Example: NDFirewall::scan($request->input('search')).
     */
    public function scan(mixed $value, ?array $categories = null): ScanResult
    {
        try {
            $rules = RuleSet::active($categories ?? $this->config['categories'] ?? []);

            return $this->scanner()->scanValue($value, $rules);
        } catch (Throwable $e) {
            $this->logRaw('ndfirewall engine error during scan(): '.$e->getMessage());

            return ScanResult::engineFailed($e->getMessage());
        }
    }

    public function shouldBlock(ScanResult $result): bool
    {
        if (($this->config['mode'] ?? 'block') !== 'block') {
            return false;
        }

        $threshold = (int) ($this->config['block_threshold'] ?? 3);

        return ! $result->clean && $result->highestSeverity >= $threshold;
    }

    private function scanner(): Scanner
    {
        return new Scanner(
            (int) ($this->config['max_field_length'] ?? 8192),
            (int) ($this->config['pcre_backtrack_limit'] ?? 200000),
        );
    }

    private function extractTarget(Request $request, string $target): array
    {
        return match ($target) {
            'query' => $request->query->all(),
            'post' => is_array($request->post()) ? $request->post() : [],
            'cookies' => $request->cookie() ?? [],
            'headers' => $this->flattenHeaders($request),
            'path' => ['__path' => $request->path()],
            'body' => ['__raw' => $request->getContent()],
            default => [],
        };
    }

    private function flattenHeaders(Request $request): array
    {
        $out = [];
        foreach ($request->headers->all() as $name => $values) {
            $out[$name] = implode(' ', array_map('strval', (array) $values));
        }

        return $out;
    }

    private function log(ScanResult $result, Request $request): void
    {
        if ($result->clean && $result->engineError === null) {
            return;
        }

        if ($result->engineError !== null) {
            $this->logRaw('ndfirewall engine error: '.$result->engineError);

            return;
        }

        $this->logRaw(sprintf(
            'ndfirewall match on %s %s from %s: %s',
            $this->sanitizeForLog($request->getMethod()),
            $this->sanitizeForLog($request->path()),
            $this->sanitizeForLog((string) $request->ip()),
            $this->sanitizeForLog((string) json_encode($result->matches)),
        ));
    }

    /**
     * Every piece of attacker-controlled data (path, matched field names,
     * etc.) goes through here before it reaches a log line. Without this,
     * a request path or header containing \n/\r could forge fake log
     * entries or break log-parsing tools (log injection) — the message
     * itself is otherwise built from raw $request values.
     */
    private function sanitizeForLog(string $value): string
    {
        return preg_replace('/[\x00-\x1F\x7F]/', ' ', $value) ?? '(unloggable value)';
    }

    private function logRaw(string $message): void
    {
        $channel = $this->config['log_channel'] ?? null;

        try {
            if ($channel) {
                Log::channel($channel)->warning($message);
            } else {
                Log::warning($message);
            }
        } catch (Throwable) {
            // Logging must never be able to break a request either.
        }
    }
}
