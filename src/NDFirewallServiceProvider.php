<?php

namespace NDFirewall;

use Illuminate\Support\ServiceProvider;
use NDFirewall\Http\Middleware\NDFirewallMiddleware;

class NDFirewallServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/ndfirewall.php', 'ndfirewall');

        $this->app->singleton('ndfirewall', function ($app) {
            return new NDFirewallManager($app['config']['ndfirewall'] ?? []);
        });

        $this->app->alias('ndfirewall', NDFirewallManager::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/ndfirewall.php' => config_path('ndfirewall.php'),
            ], 'ndfirewall-config');
        }

        /** @var \Illuminate\Routing\Router $router */
        $router = $this->app['router'];

        // Registered as an alias only — NOT pushed onto any global
        // middleware group. It only ever runs on routes that explicitly
        // opt in with ->middleware('ndfirewall').
        $router->aliasMiddleware('ndfirewall', NDFirewallMiddleware::class);

        $this->app->when(NDFirewallMiddleware::class)
            ->needs('$config')
            ->give(fn ($app) => $app['config']['ndfirewall'] ?? []);
    }
}
