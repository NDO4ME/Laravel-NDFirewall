<?php

namespace NDFirewall\Engine;

use NDFirewall\Engine\Rules\Deserialization;
use NDFirewall\Engine\Rules\PathTraversal;
use NDFirewall\Engine\Rules\Rce;
use NDFirewall\Engine\Rules\Sqli;
use NDFirewall\Engine\Rules\Ssrf;
use NDFirewall\Engine\Rules\Xss;

/**
 * Collects and caches the active rule list for a given category config.
 * Rules are plain data (id/category/description/severity/pattern/targets) —
 * this class never executes anything from a rule beyond preg_match on its
 * own hardcoded 'pattern' field.
 */
class RuleSet
{
    /** @var array<string, callable> */
    private static array $providers = [
        'sqli' => [Sqli::class, 'rules'],
        'xss' => [Xss::class, 'rules'],
        'rce' => [Rce::class, 'rules'],
        'path_traversal' => [PathTraversal::class, 'rules'],
        'ssrf' => [Ssrf::class, 'rules'],
        'deserialization' => [Deserialization::class, 'rules'],
    ];

    /** @var array<string, array>|null */
    private static ?array $cache = null;

    /**
     * @param array<string, bool> $enabledCategories
     * @return array<int, array>
     */
    public static function active(array $enabledCategories): array
    {
        if (self::$cache === null) {
            self::$cache = [];
            foreach (self::$providers as $category => $provider) {
                self::$cache[$category] = Obfuscator::cleanRules(call_user_func($provider));
            }
        }

        $rules = [];
        foreach (self::$cache as $category => $categoryRules) {
            if (! empty($enabledCategories[$category])) {
                foreach ($categoryRules as $rule) {
                    $rules[] = $rule;
                }
            }
        }

        return $rules;
    }

    /**
     * Register custom rules (e.g. from a developer's own app). Genuinely
     * additive: if $category matches a built-in one (e.g. 'rce'), the new
     * rules are appended alongside the built-in ones rather than replacing
     * them — a developer reusing a built-in category name by mistake can't
     * silently disable that category's default detection.
     */
    public static function extend(string $category, callable $provider): void
    {
        $previous = self::$providers[$category] ?? null;

        self::$providers[$category] = $previous
            ? fn () => array_merge(call_user_func($previous), call_user_func($provider))
            : $provider;

        self::$cache = null;
    }
}
