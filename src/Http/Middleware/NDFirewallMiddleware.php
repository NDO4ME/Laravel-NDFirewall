<?php

namespace NDFirewall\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use NDFirewall\NDFirewallManager;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Route-scoped middleware. Nothing runs globally unless you register it
 * globally yourself — apply it to exactly the routes/groups you want:
 *
 *   Route::middleware('ndfirewall')->group(fn () => ...);
 *   Route::post('/search', ...)->middleware('ndfirewall:query,post');
 *
 * The optional parameters after ':' restrict which input sources this
 * particular route scans (defaults to config('ndfirewall.default_targets')).
 *
 * This class is intentionally the only place that can produce a blocking
 * HTTP response. Everything below it (Manager, Scanner) only ever reports
 * findings — it never aborts a request itself. And this class's own
 * handle() is wrapped so that whatever happens inside, a request that
 * reaches a misconfigured/broken NDFirewall install is passed through,
 * not dropped.
 */
class NDFirewallMiddleware
{
    public function __construct(private readonly NDFirewallManager $ndfirewall, private readonly array $config)
    {
    }

    public function handle(Request $request, Closure $next, string ...$targets): Response
    {
        try {
            if (! ($this->config['enabled'] ?? true)) {
                return $next($request);
            }

            $result = $this->ndfirewall->scanRequest($request, $targets ?: null);

            if ($result->engineError !== null) {
                return $this->handleEngineFailure($request, $next);
            }

            if (! $result->clean && $this->ndfirewall->shouldBlock($result)) {
                return response(
                    $this->config['block_message'] ?? 'Request blocked.',
                    (int) ($this->config['block_status'] ?? 403)
                );
            }

            return $next($request);
        } catch (Throwable $e) {
            // Absolute last line of defense: whatever went wrong, wrong
            // integration or not, NDFirewall must never be the reason a
            // legitimate request fails.
            return $this->handleEngineFailure($request, $next);
        }
    }

    private function handleEngineFailure(Request $request, Closure $next): Response
    {
        if (($this->config['on_internal_error'] ?? 'open') === 'closed') {
            return response('Service temporarily unavailable.', 503);
        }

        return $next($request);
    }
}
