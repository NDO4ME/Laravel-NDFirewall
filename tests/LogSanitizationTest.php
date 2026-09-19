<?php

namespace NDFirewall\Tests;

use NDFirewall\NDFirewallManager;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

class LogSanitizationTest extends TestCase
{
    public function test_log_injection_via_newlines_is_stripped(): void
    {
        $manager = new NDFirewallManager([]);
        $method = new ReflectionMethod(NDFirewallManager::class, 'sanitizeForLog');

        $malicious = "/legit-path\n[2026-01-01] FAKE ADMIN LOGIN SUCCESS from 1.2.3.4\r\nX-Injected: 1";

        $clean = $method->invoke($manager, $malicious);

        $this->assertStringNotContainsString("\n", $clean);
        $this->assertStringNotContainsString("\r", $clean);
    }
}
