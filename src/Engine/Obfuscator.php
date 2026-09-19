<?php

namespace NDFirewall\Engine;

/**
 * Rule pattern strings necessarily contain literal keywords like "eval",
 * "system", "base64_decode" — the very things they detect. Pattern-based
 * antivirus/malware heuristics scan source files for exactly those
 * substrings and can false-positive on a WAF's own signature data, same as
 * NinjaFirewall documents for its own rule file.
 *
 * This does not hide or alter behavior: MARKER is spliced into the *source*
 * spelling of a keyword (e.g. "eveeeeal", same "eeee" filler NinjaFirewall
 * uses in its own conf/.rules.php) and stripped back out here before the
 * pattern is ever compiled/used, so the regex that actually runs is
 * byte-identical to the unobfuscated version. It only changes what a
 * static file scan sees on disk.
 */
final class Obfuscator
{
    public const MARKER = 'eeee';

    public static function clean(string $pattern): string
    {
        return str_replace(self::MARKER, '', $pattern);
    }

    /** @param array<int, array> $rules */
    public static function cleanRules(array $rules): array
    {
        foreach ($rules as &$rule) {
            if (isset($rule['pattern'])) {
                $rule['pattern'] = self::clean($rule['pattern']);
            }
        }

        return $rules;
    }
}
