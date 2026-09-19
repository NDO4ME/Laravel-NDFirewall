<?php

namespace NDFirewall\Engine\Rules;

class Ssrf
{
    public static function rules(): array
    {
        return [
            [
                'id' => 'ssrf-metadata-endpoint',
                'category' => 'ssrf',
                'description' => 'cloud metadata endpoint access attempt (169.254.169.254)',
                'severity' => 5,
                'pattern' => '/169\.254\.169\.254|metadata\.google\.internal/i',
            ],
            [
                'id' => 'ssrf-loopback-target',
                'category' => 'ssrf',
                'description' => 'request targeting loopback/localhost as a URL parameter',
                'severity' => 3,
                'pattern' => '/\b(?:https?:\/\/)?(?:127\.0\.0\.1|0\.0\.0\.0|localhost)(?::\d+)?\b/i',
            ],
            [
                'id' => 'ssrf-internal-range',
                'category' => 'ssrf',
                'description' => 'request targeting an RFC1918 private IP range',
                'severity' => 3,
                'pattern' => '/\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b/',
            ],
            [
                'id' => 'ssrf-alt-schemes',
                'category' => 'ssrf',
                'description' => 'non-HTTP scheme in a URL-shaped parameter (file://, gopher://, dict://)',
                'severity' => 4,
                'pattern' => '/\b(?:file|gopher|dict|ftp):\/\//i',
            ],
        ];
    }
}
