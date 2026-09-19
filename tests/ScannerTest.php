<?php

namespace NDFirewall\Tests;

use NDFirewall\Engine\RuleSet;
use NDFirewall\Engine\Scanner;
use PHPUnit\Framework\TestCase;

class ScannerTest extends TestCase
{
    private function allRules(): array
    {
        return RuleSet::active([
            'sqli' => true,
            'xss' => true,
            'rce' => true,
            'path_traversal' => true,
            'ssrf' => true,
            'deserialization' => true,
        ]);
    }

    /** @dataProvider maliciousPayloads */
    public function test_it_detects_known_malicious_payloads(string $target, string $field, string $payload, string $expectedCategory): void
    {
        $scanner = new Scanner();
        $result = $scanner->scan([$target => [$field => $payload]], $this->allRules());

        $this->assertFalse($result->clean, "Expected payload to be flagged: {$payload}");
        $this->assertContains(
            $expectedCategory,
            array_column($result->matches, 'category'),
            "Expected category {$expectedCategory} for payload: {$payload}"
        );
    }

    public static function maliciousPayloads(): array
    {
        return [
            'sqli union select' => ['query', 'id', "1 UNION SELECT username,password FROM users", 'sqli'],
            'sqli boolean blind' => ['query', 'id', "1' OR '1'='1", 'sqli'],
            'sqli stacked query' => ['post', 'name', "test'; DROP TABLE users; --", 'sqli'],
            'sqli sleep' => ['query', 'id', "1 AND SLEEP(5)", 'sqli'],
            'xss script tag' => ['post', 'comment', '<script>alert(document.cookie)</script>', 'xss'],
            'xss event handler' => ['post', 'name', '<img src=x onerror=alert(1)>', 'xss'],
            'xss javascript uri' => ['query', 'redirect', 'javascript:alert(1)', 'xss'],
            'xss ontoggle handler' => ['post', 'comment', '<details open ontoggle=alert(1)>', 'xss'],
            'xss onstart handler' => ['post', 'comment', '<marquee onstart=alert(1)>', 'xss'],
            'xss data uri html' => ['post', 'comment', 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==', 'xss'],
            'xss tag splitting' => ['post', 'comment', '<scr<script>ipt>alert(1)</scr</script>ipt>', 'xss'],
            'rce system call' => ['post', 'cmd', 'system("id");', 'rce'],
            'rce eval' => ['post', 'code', 'eval($_GET[1]);', 'rce'],
            'rce php wrapper' => ['query', 'file', 'php://filter/convert.base64-encode/resource=index', 'rce'],
            'path traversal' => ['query', 'file', '../../../../etc/passwd', 'path_traversal'],
            'path traversal encoded' => ['query', 'file', '%2e%2e%2f%2e%2e%2fetc/passwd', 'path_traversal'],
            'ssrf metadata' => ['post', 'url', 'http://169.254.169.254/latest/meta-data/', 'ssrf'],
            'ssrf gopher' => ['post', 'url', 'gopher://127.0.0.1:6379/_INFO', 'ssrf'],
            'deser php object' => ['post', 'data', 'O:8:"stdClass":1:{s:1:"a";s:1:"b";}', 'deserialization'],
        ];
    }

    /** @dataProvider legitimatePayloads */
    public function test_it_does_not_flag_legitimate_input(string $target, string $field, string $value): void
    {
        $scanner = new Scanner();
        $result = $scanner->scan([$target => [$field => $value]], $this->allRules());

        $this->assertTrue($result->clean, "Expected legitimate value NOT to be flagged: {$value}");
    }

    public static function legitimatePayloads(): array
    {
        return [
            'normal name' => ['post', 'name', 'Ertuğrul Tuncer'],
            'normal email' => ['post', 'email', 'user@example.com'],
            'normal search' => ['query', 'q', 'laravel middleware best practices'],
            'normal sentence with and/or words' => ['post', 'bio', 'I like cats and dogs, or maybe just cats.'],
            'private ip mention without url' => ['post', 'note', 'the office wifi is fine today'],
            'json-ish but not serialized php' => ['post', 'payload', '{"name":"test","value":123}'],
            'word starting with on #1' => ['query', 'status', 'online=1'],
            'word starting with on #2' => ['query', 'status', 'once=true'],
            'word starting with on #3' => ['post', 'source', 'onboarding=yes'],
            'sentence containing on as a word' => ['post', 'bio', 'I am going on a trip soon'],
        ];
    }

    public function test_scan_never_throws_on_malformed_or_binary_input(): void
    {
        $scanner = new Scanner();

        $weirdInputs = [
            "\xFF\xFE\x00\x01binary garbage \x00\x00",
            str_repeat('a(', 50000), // pathological nesting attempt
            str_repeat('../', 5000), // long traversal chain
            null,
        ];

        foreach ($weirdInputs as $i => $input) {
            $result = $scanner->scan(['post' => ['field'.$i => $input]], $this->allRules());
            // Must always return a ScanResult object, never throw.
            $this->assertNotNull($result);
        }

        $this->addToAssertionCount(1);
    }

    public function test_oversized_field_is_truncated_not_rejected(): void
    {
        $scanner = new Scanner(maxFieldLength: 100);
        $huge = str_repeat('x', 10000).' <script>alert(1)</script>';

        $result = $scanner->scan(['post' => ['field' => $huge]], $this->allRules());

        // The attack payload is past the truncation point, so it must be
        // considered clean rather than the engine choking on a huge string.
        $this->assertTrue($result->clean);
    }

    public function test_scanner_never_executes_matched_payload(): void
    {
        // A payload that, if it were ever passed to eval/create_function/etc,
        // would create a marker file. If this test's tmp marker exists after
        // scanning, the engine executed attacker input — which must never
        // happen since Scanner only calls preg_match on values.
        $marker = sys_get_temp_dir().'/ndfirewall_exec_marker_'.uniqid();
        $payload = "'; file_put_contents('{$marker}', 'PWNED'); //";

        $scanner = new Scanner();
        $scanner->scan(['post' => ['field' => $payload]], $this->allRules());

        $this->assertFileDoesNotExist($marker);
    }
}
