<?php

namespace NDFirewall\Facades;

use Illuminate\Support\Facades\Facade;
use NDFirewall\Engine\ScanResult;

/**
 * @method static ScanResult scan(mixed $value, ?array $categories = null)
 * @method static ScanResult scanRequest(\Illuminate\Http\Request $request, ?array $targets = null)
 * @method static bool shouldBlock(ScanResult $result)
 *
 * @see \NDFirewall\NDFirewallManager
 */
class NDFirewall extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'ndfirewall';
    }
}
