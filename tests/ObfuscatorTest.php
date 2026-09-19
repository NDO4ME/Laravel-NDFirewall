<?php

namespace NDFirewall\Tests;

use NDFirewall\Engine\Obfuscator;
use NDFirewall\Engine\RuleSet;
use NDFirewall\Engine\Scanner;
use PHPUnit\Framework\TestCase;

class ObfuscatorTest extends TestCase
{
    public function test_marker_is_stripped_cleanly(): void
    {
        $this->assertSame('eval', Obfuscator::clean('ev'.Obfuscator::MARKER.'al'));
        $this->assertSame(
            '/\bsystem\s*\(/i',
            Obfuscator::clean('/\bsyseeeetem\s*\(/i')
        );
    }

    public function test_rce_source_file_does_not_contain_raw_sensitive_keywords(): void
    {
        $source = file_get_contents(__DIR__.'/../src/Engine/Rules/Rce.php');

        foreach (['eval(', 'system(', 'exec(', 'assert(', 'base64_decode('] as $needle) {
            $this->assertStringNotContainsString(
                $needle,
                $source,
                "Expected obfuscated source to NOT contain literal '{$needle}'"
            );
        }
    }

    public function test_obfuscation_does_not_change_actual_detection_behaviour(): void
    {
        $scanner = new Scanner();
        $rules = RuleSet::active(['rce' => true]);

        $result = $scanner->scan(['post' => ['cmd' => 'system("id");']], $rules);

        $this->assertFalse($result->clean);
        $this->assertSame('rce', $result->matches[0]['category']);
    }
}
