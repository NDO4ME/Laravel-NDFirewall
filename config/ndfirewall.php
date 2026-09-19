<?php

return [

    /*
    |--------------------------------------------------------------------
    | Global switch
    |--------------------------------------------------------------------
    | If false, the middleware and NDFirewall::scan() become no-ops that
    | always let the request through untouched. Useful for a kill switch
    | in production without touching route definitions.
    */
    'enabled' => env('NDFIREWALL_ENABLED', true),

    /*
    |--------------------------------------------------------------------
    | Fail-open (safety)
    |--------------------------------------------------------------------
    | If the engine throws internally (bad regex, misconfiguration, a bug)
    | this decides what happens to the request. 'open' means the request
    | is always allowed through and the error is logged — a broken WAF
    | must never be able to take an application down or block legitimate
    | traffic. This should almost never be changed to 'closed'.
    */
    'on_internal_error' => env('NDFIREWALL_ON_ERROR', 'open'), // 'open' | 'closed'

    /*
    |--------------------------------------------------------------------
    | Mode
    |--------------------------------------------------------------------
    | 'block'   - matching requests above the block threshold are rejected.
    | 'monitor' - nothing is ever blocked, only logged. Good for a first
    |             rollout to see what would have triggered before enabling
    |             enforcement on a route.
    */
    'mode' => env('NDFIREWALL_MODE', 'block'),

    /*
    |--------------------------------------------------------------------
    | Severity threshold to block
    |--------------------------------------------------------------------
    | Rules carry a severity 1 (low) .. 5 (critical). In 'block' mode,
    | only matches >= this threshold are rejected; lower ones are logged
    | only. Keeps noisy/low-confidence rules from breaking real traffic.
    */
    'block_threshold' => (int) env('NDFIREWALL_BLOCK_THRESHOLD', 3),

    /*
    |--------------------------------------------------------------------
    | Logging
    |--------------------------------------------------------------------
    | Any Laravel log channel. Set to null to disable logging entirely.
    */
    'log_channel' => env('NDFIREWALL_LOG_CHANNEL', null), // null = default channel

    /*
    |--------------------------------------------------------------------
    | Response when blocked
    |--------------------------------------------------------------------
    */
    'block_status' => 403,
    'block_message' => 'Request blocked.',

    /*
    |--------------------------------------------------------------------
    | Input sources scanned by default
    |--------------------------------------------------------------------
    | Rules can override this per-rule via their own "targets" list.
    | Keeping this narrow by default is what keeps NDFirewall cheap:
    | only scan what a route actually needs scanned.
    */
    'default_targets' => ['query', 'post', 'cookies', 'path'],

    /*
    |--------------------------------------------------------------------
    | Max input length scanned per field
    |--------------------------------------------------------------------
    | Guards against pathological/huge inputs blowing up regex time.
    | Values longer than this are truncated before matching (truncation
    | itself is logged as suspicious separately if enabled below).
    */
    'max_field_length' => (int) env('NDFIREWALL_MAX_FIELD_LEN', 8192),

    /*
    |--------------------------------------------------------------------
    | PCRE safety
    |--------------------------------------------------------------------
    | Backtrack/recursion limits applied only while NDFirewall runs its
    | own matching, then restored — prevents a crafted payload from
    | causing catastrophic backtracking / ReDoS inside the WAF itself.
    */
    'pcre_backtrack_limit' => (int) env('NDFIREWALL_PCRE_BACKTRACK_LIMIT', 200000),

    /*
    |--------------------------------------------------------------------
    | Rule categories enabled
    |--------------------------------------------------------------------
    | Toggle whole categories on/off. See src/Engine/Rules/*.
    */
    'categories' => [
        'sqli'            => true,
        'xss'             => true,
        'rce'             => true,
        'path_traversal'  => true,
        'ssrf'            => true,
        'deserialization' => true,
    ],

];
