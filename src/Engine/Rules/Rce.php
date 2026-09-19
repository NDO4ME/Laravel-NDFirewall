<?php

namespace NDFirewall\Engine\Rules;

/**
 * Keyword literals below carry the "eeee" filler NinjaFirewall also uses in
 * its own rule file, stripped at load time by NDFirewall\Engine\Obfuscator.
 * Purely to avoid pattern-matching AV heuristics flagging our own detection
 * data (see README "Antivirus false positives") — the compiled regex is
 * identical to the unobfuscated version.
 */
class Rce
{
    public static function rules(): array
    {
        return [
            [
                'id' => 'rce-php-exec-functions',
                'category' => 'rce',
                'description' => 'PHP command execution function call (system/exec/shell_exec/passthru/proc_open)',
                'severity' => 5,
                'pattern' => '/\b(?:syseeeetem|exeeeec|shell_exeeeec|passeeeethru|proc_opeeeeen|popeeeeen|pcntl_exeeeec)\s*\(/i',
            ],
            [
                'id' => 'rce-php-eval',
                'category' => 'rce',
                'description' => 'PHP eval / assert style code execution',
                'severity' => 5,
                'pattern' => '/\b(?:eveeeeal|asseeeeert)\s*\(/i',
            ],
            [
                'id' => 'rce-php-dynamic-call',
                'category' => 'rce',
                'description' => 'dynamic function call helpers often used to smuggle RCE (call_user_func, create_function)',
                'severity' => 4,
                'pattern' => '/\b(?:call_useeeeer_funeeeec(?:_array)?|creeeeeate_funceeeetion)\s*\(/i',
            ],
            [
                'id' => 'rce-shell-metachars',
                'category' => 'rce',
                'description' => 'shell metacharacter chaining typical of OS command injection',
                'severity' => 4,
                'pattern' => '/[;&|`]\s*(?:cat|ls|whoami|id|uname|wget|curl|nc|bash|sh)\b/i',
            ],
            [
                'id' => 'rce-backtick-exec',
                'category' => 'rce',
                'description' => 'backtick shell execution',
                'severity' => 4,
                'pattern' => '/`[^`]{1,200}`/',
            ],
            [
                'id' => 'rce-php-wrapper',
                'category' => 'rce',
                'description' => 'php:// stream wrapper abuse (input/filter/data for RFI/RCE chains)',
                'severity' => 5,
                'pattern' => '/php:\/\/(?:ineeeeput|fileeeeter|dateeeea)/i',
            ],
            [
                'id' => 'rce-base64-decode-chain',
                'category' => 'rce',
                'description' => 'base64_decode chained into eval/system (common webshell obfuscation)',
                'severity' => 4,
                'pattern' => '/(?:eveeeeal|syseeeetem|asseeeeert)\s*\(\s*base64_deeeecode\s*\(/i',
            ],
        ];
    }
}
