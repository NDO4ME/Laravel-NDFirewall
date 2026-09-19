<?php

namespace NDFirewall\Engine\Rules;

class PathTraversal
{
    public static function rules(): array
    {
        return [
            [
                'id' => 'path-dotdot-traversal',
                'category' => 'path_traversal',
                'description' => 'directory traversal (../ or ..\\)',
                'severity' => 4,
                'pattern' => '/(?:\.\.[\/\\\\]){2,}/',
            ],
            [
                'id' => 'path-encoded-traversal',
                'category' => 'path_traversal',
                'description' => 'URL-encoded directory traversal (%2e%2e%2f)',
                'severity' => 4,
                'pattern' => '/%2e%2e(?:%2f|%5c|\/|\\\\)/i',
            ],
            [
                'id' => 'path-sensitive-files',
                'category' => 'path_traversal',
                'description' => 'access to well-known sensitive files',
                'severity' => 4,
                'pattern' => '/\b(?:etc\/passwd|etc\/shadow|win\.ini|boot\.ini|\.env|\.ssh\/id_rsa)\b/i',
            ],
            [
                'id' => 'path-null-byte',
                'category' => 'path_traversal',
                'description' => 'null byte injection to truncate file paths',
                'severity' => 4,
                'pattern' => '/%00|\x00/',
            ],
            [
                'id' => 'path-lfi-wrapper',
                'category' => 'path_traversal',
                'description' => 'LFI via stream wrappers (data://, expect://, zip://, phar://)',
                'severity' => 5,
                'pattern' => '/(?:data|expect|zip|phar|glob):\/\//i',
            ],
        ];
    }
}
