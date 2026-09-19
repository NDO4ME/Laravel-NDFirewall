<?php

namespace NDFirewall\Engine;

/**
 * Immutable, plain-data result of a scan. Never carries a Closure or
 * anything callable — safe to log, serialize, or hand to application code.
 */
final class ScanResult
{
    /** @param array<int, array{id:string,category:string,description:string,severity:int,target:string,field:string}> $matches */
    public function __construct(
        public readonly bool $clean,
        public readonly array $matches,
        public readonly int $highestSeverity,
        public readonly ?string $engineError = null,
    ) {
    }

    public static function ok(): self
    {
        return new self(true, [], 0);
    }

    /** @param array<int, array> $matches */
    public static function flagged(array $matches): self
    {
        $highest = 0;
        foreach ($matches as $m) {
            $highest = max($highest, $m['severity']);
        }

        return new self(false, $matches, $highest);
    }

    public static function engineFailed(string $error): self
    {
        // A failed engine is reported as "clean" for request-flow purposes —
        // the caller (middleware) decides pass/block based on config
        // ('on_internal_error'), never based on this object claiming a
        // false positive/negative on its own.
        return new self(true, [], 0, $error);
    }
}
