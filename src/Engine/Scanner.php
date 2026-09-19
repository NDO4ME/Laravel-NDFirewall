<?php

namespace NDFirewall\Engine;

use Throwable;

/**
 * Read-only detection engine.
 *
 * Safety invariants (do not relax these without re-reading why they exist):
 *  1. Input values are only ever passed to preg_match(). They are never
 *     passed to eval, include/require, unserialize, call_user_func,
 *     exec/system, or any other sink. A malicious payload can make a rule
 *     *match*; it can never make this class *do* anything with the payload.
 *  2. Every scan() call is wrapped in try/catch(\Throwable). A broken
 *     regex, an out-of-memory, a PCRE engine error — none of it can bubble
 *     up and take the request down. Callers get a ScanResult either way.
 *  3. PCRE backtrack/recursion limits are lowered for the duration of the
 *     scan and restored afterwards, so a pathological input can't burn
 *     CPU inside the WAF itself (ReDoS-on-the-WAF).
 *  4. Oversized fields are truncated before matching, not rejected — a
 *     huge field is a performance concern, not by itself an attack.
 */
class Scanner
{
    public function __construct(
        private readonly int $maxFieldLength = 8192,
        private readonly int $pcreBacktrackLimit = 200000,
    ) {
    }

    /**
     * @param array<string, array<string, mixed>> $inputsByTarget e.g. ['query' => [...], 'post' => [...]]
     * @param array<int, array> $rules
     */
    public function scan(array $inputsByTarget, array $rules): ScanResult
    {
        $originalBacktrack = @ini_get('pcre.backtrack_limit');
        $originalRecursion = @ini_get('pcre.recursion_limit');

        try {
            @ini_set('pcre.backtrack_limit', (string) $this->pcreBacktrackLimit);
            @ini_set('pcre.recursion_limit', (string) $this->pcreBacktrackLimit);

            $matches = [];

            foreach ($rules as $rule) {
                $targets = $rule['targets'] ?? array_keys($inputsByTarget);

                foreach ($targets as $target) {
                    if (! isset($inputsByTarget[$target])) {
                        continue;
                    }

                    foreach ($inputsByTarget[$target] as $field => $value) {
                        $hit = $this->matchOne($rule, $target, (string) $field, $value);
                        if ($hit !== null) {
                            $matches[] = $hit;
                        }
                    }
                }
            }

            return empty($matches) ? ScanResult::ok() : ScanResult::flagged($matches);
        } catch (Throwable $e) {
            return ScanResult::engineFailed($e->getMessage());
        } finally {
            if ($originalBacktrack !== false) {
                @ini_set('pcre.backtrack_limit', $originalBacktrack);
            }
            if ($originalRecursion !== false) {
                @ini_set('pcre.recursion_limit', $originalRecursion);
            }
        }
    }

    /**
     * Scan a single arbitrary value (used by the NDFirewall::scan() facade
     * for developers who want to check one field/argument programmatically
     * instead of a whole request).
     */
    public function scanValue(mixed $value, array $rules, string $target = 'manual', string $field = 'value'): ScanResult
    {
        try {
            $matches = [];
            foreach ($rules as $rule) {
                $hit = $this->matchOne($rule, $target, $field, $value);
                if ($hit !== null) {
                    $matches[] = $hit;
                }
            }

            return empty($matches) ? ScanResult::ok() : ScanResult::flagged($matches);
        } catch (Throwable $e) {
            return ScanResult::engineFailed($e->getMessage());
        }
    }

    private function matchOne(array $rule, string $target, string $field, mixed $value): ?array
    {
        // Only scalar-ish values are matched directly; arrays/objects are
        // flattened shallowly so nested input doesn't silently escape
        // detection, but we never attempt to serialize/execute them.
        if (is_array($value)) {
            foreach ($value as $k => $v) {
                $hit = $this->matchOne($rule, $target, $field.'.'.$k, $v);
                if ($hit !== null) {
                    return $hit;
                }
            }

            return null;
        }

        if (! is_scalar($value)) {
            return null;
        }

        $subject = (string) $value;
        if (strlen($subject) > $this->maxFieldLength) {
            $subject = substr($subject, 0, $this->maxFieldLength);
        }

        if ($subject === '') {
            return null;
        }

        // @-suppressed: a malformed pattern must not throw a warning that
        // escapes this method. preg_match returning false is handled below.
        $result = @preg_match($rule['pattern'], $subject);

        if ($result === 1) {
            return [
                'id' => $rule['id'],
                'category' => $rule['category'],
                'description' => $rule['description'],
                'severity' => $rule['severity'],
                'target' => $target,
                'field' => $field,
            ];
        }

        return null;
    }
}
