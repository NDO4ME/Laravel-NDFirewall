# NDFirewall [Development has been discontinued]

A lightweight, route-scoped Web Application Firewall for Laravel. No admin
panel — it's a service you call from code. Detects RCE, SQL injection, XSS,
LFI/RFI/path traversal, SSRF and PHP object injection payloads via regex,
without ever executing anything it matches.

Built to be the opposite of a heavyweight, always-on WAF: attach it only to
the routes/fields that actually need it, and trust that a bug or a bad
integration in NDFirewall itself can never take your application down.

## Why

Most PHP WAFs (NinjaFirewall included) hook every single request globally
through `auto_prepend_file` and run a large, fixed signature set on every
field of every request. NDFirewall instead is:

- **Opt-in per route** — apply it with `->middleware('ndfirewall')` on
  exactly the routes you want, or call `NDFirewall::scan()` on a single
  field/argument. Nothing runs unless you ask it to.
- **Fail-open by design** — every layer (`Scanner`, `NDFirewallManager`,
  the middleware itself) is wrapped in `try/catch(Throwable)`. An internal
  error, a malformed custom rule, or a wrong integration can never crash or
  block a legitimate request; it logs and lets the request through
  (configurable via `ndfirewall.on_internal_error`).
- **Detection only, never execution** — matched input is only ever passed
  to `preg_match()`. It is never `eval`'d, `include`d, `unserialize`d, or
  passed to `call_user_func`/`exec`. A malicious payload can make a rule
  match; it can never make NDFirewall *do* anything with it.
- **No admin panel, no dashboard** — just a Composer package, a config
  file, and a facade. Logging goes through your own Laravel log channels.

## Install

```bash
composer require ndfirewall/laravel-waf
php artisan vendor:publish --tag=ndfirewall-config
```

## Usage — route-scoped (recommended)

Nothing runs globally by default. Attach it to exactly the routes you want:

```php
Route::middleware('ndfirewall')->group(function () {
    Route::post('/contact', ContactController::class);
});

// Restrict which parts of the request are scanned on this route:
Route::post('/search', SearchController::class)->middleware('ndfirewall:query,post');

// Or apply it globally in app/Http/Kernel.php if you actually want that:
// protected $middleware = [..., \NDFirewall\Http\Middleware\NDFirewallMiddleware::class];
```

## Usage — programmatic (one field/function, no route needed)

```php
use NDFirewall\Facades\NDFirewall;

$result = NDFirewall::scan($request->input('comment'));

if (! $result->clean) {
    // $result->matches, $result->highestSeverity
    abort(403);
}
```

`NDFirewall::scan()` and `NDFirewall::scanRequest()` never throw — a bug or
misconfiguration inside NDFirewall can never crash or block a request by
accident.

## Modes

- `mode = block` (default): matches at/above `block_threshold` (default 3,
  scale 1-5) are rejected with `block_status` (403).
- `mode = monitor`: nothing is ever blocked, only logged — useful for
  rolling NDFirewall onto a route and watching logs before enforcing it.

## Safety guarantees

- Every scan is wrapped in try/catch; the middleware's own `handle()` is
  wrapped again as a last line of defense.
- Matched input is only ever passed to `preg_match()` — never executed.
- PCRE backtrack/recursion limits are capped during scanning and restored
  afterward, so a crafted payload can't cause the WAF itself to hang.
- Oversized fields are truncated, not rejected — large legitimate uploads
  don't get treated as attacks.
- All attacker-influenced data (request path, etc.) is stripped of control
  characters before it reaches a log line, to prevent log injection.
- `RuleSet::extend()` is genuinely additive: reusing a built-in category
  name (e.g. `'rce'`) merges your rules alongside the defaults instead of
  silently replacing them.
- Rule pattern strings that contain literal exploit keywords (`eval`,
  `system`, `base64_decode`, ...) are lightly obfuscated on disk — the same
  technique NinjaFirewall uses in its own rule file — purely so
  pattern-matching antivirus/malware scanners don't flag the WAF's own
  signature data as malicious. The compiled regex used at runtime is
  byte-identical either way.

## Extending rules

```php
use NDFirewall\Engine\RuleSet;

RuleSet::extend('custom', fn () => [
    [
        'id' => 'custom-1',
        'category' => 'custom',
        'description' => 'block a specific internal admin token leaking out',
        'severity' => 4,
        'pattern' => '/ADMIN_SECRET_[A-Z0-9]{16}/',
    ],
]);
```

Then enable the category in `config/ndfirewall.php` under `categories`.

## Known limitations

- This is a starter signature set (~40 rules across 6 categories), not a
  mature, battle-tested ruleset like NinjaFirewall's 125+ rules refined
  over years of production traffic. Expect to extend it for your threat
  model.
- Regex-based detection cannot decode nested/chained encodings (e.g. double
  base64, unicode escape chains) — it matches what's on the wire, not what
  a browser/interpreter would eventually decode it into.
- It's a second layer of defense, not a replacement for secure coding:
  parameterized queries for SQL, Blade's `{{ }}` auto-escaping / `htmlspecialchars`
  for output, etc. still matter.
- Only tested with isolated PHPUnit tests so far (`tests/`); not yet
  exercised against a live Laravel app under real traffic.

## Tests

```bash
composer install
vendor/bin/phpunit
```

## License

MIT
