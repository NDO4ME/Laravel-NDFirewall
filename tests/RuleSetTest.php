<?php

namespace NDFirewall\Tests;

use NDFirewall\Engine\RuleSet;
use PHPUnit\Framework\TestCase;

class RuleSetTest extends TestCase
{
    public function test_extending_a_builtin_category_does_not_disable_it(): void
    {
        RuleSet::extend('rce', fn () => [
            [
                'id' => 'custom-rce-test-rule',
                'category' => 'rce',
                'description' => 'test-only custom rule',
                'severity' => 3,
                'pattern' => '/my_custom_marker/',
            ],
        ]);

        $rules = RuleSet::active(['rce' => true]);
        $ids = array_column($rules, 'id');

        // The built-in rules must still be present...
        $this->assertContains('rce-php-eval', $ids);
        $this->assertContains('rce-php-exec-functions', $ids);
        // ...alongside the developer's addition.
        $this->assertContains('custom-rce-test-rule', $ids);
    }
}
