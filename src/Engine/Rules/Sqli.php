<?php

namespace NDFirewall\Engine\Rules;

/**
 * Detection only: every pattern here is matched read-only via preg_match.
 * Nothing in this file is ever eval()'d, included, or executed.
 */
class Sqli
{
    public static function rules(): array
    {
        return [
            [
                'id' => 'sqli-union-select',
                'category' => 'sqli',
                'description' => 'UNION-based SQL injection',
                'severity' => 5,
                'pattern' => '/\bunion\b(?:\s+all)?\s+select\b/i',
            ],
            [
                'id' => 'sqli-boolean-blind',
                'category' => 'sqli',
                'description' => 'Boolean-based blind SQLi (OR/AND 1=1 or quoted string tautology)',
                'severity' => 4,
                'pattern' => '/\b(?:or|and)\b\s*[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+[\'"]?/i',
            ],
            [
                'id' => 'sqli-comment-terminator',
                'category' => 'sqli',
                'description' => 'Statement terminator followed by SQL comment',
                'severity' => 4,
                'pattern' => '/;\s*(?:--|#|\/\*)/',
            ],
            [
                'id' => 'sqli-stacked-query',
                'category' => 'sqli',
                'description' => 'Stacked query (DROP/INSERT/UPDATE/DELETE after ;)',
                'severity' => 5,
                'pattern' => '/;\s*(?:drop|insert|update|delete|alter)\s+/i',
            ],
            [
                'id' => 'sqli-sleep-benchmark',
                'category' => 'sqli',
                'description' => 'Time-based blind SQLi (SLEEP/BENCHMARK/WAITFOR)',
                'severity' => 5,
                'pattern' => '/\b(?:sleep|benchmark)\s*\(|waitfor\s+delay\s+[\'"]?\d/i',
            ],
            [
                'id' => 'sqli-information-schema',
                'category' => 'sqli',
                'description' => 'information_schema enumeration',
                'severity' => 4,
                'pattern' => '/information_schema\.(?:tables|columns)/i',
            ],
            [
                'id' => 'sqli-outfile-load',
                'category' => 'sqli',
                'description' => 'INTO OUTFILE / LOAD_FILE file read-write via SQLi',
                'severity' => 5,
                'pattern' => '/\b(?:into\s+outfile|load_file)\s*\(?/i',
            ],
            [
                'id' => 'sqli-concat-obfuscation',
                'category' => 'sqli',
                'description' => 'CHAR()/CONCAT() based keyword obfuscation',
                'severity' => 3,
                'pattern' => '/\bconcat\s*\(\s*0x|\bchar\s*\(\s*\d+\s*,\s*\d+/i',
            ],
        ];
    }
}
