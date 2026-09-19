<?php

namespace NDFirewall\Engine\Rules;

class Xss
{
    public static function rules(): array
    {
        return [
            [
                'id' => 'xss-script-tag',
                'category' => 'xss',
                'description' => '<script> tag injection',
                'severity' => 5,
                'pattern' => '/<script\b[^>]*>/i',
            ],
            [
                // Curated list rather than a bare \bon[a-z]+= — that generic
                // form false-positives on ordinary words like "online=1" or
                // "once=true". Every suffix below is a real HTML/DOM event.
                'id' => 'xss-event-handler',
                'category' => 'xss',
                'description' => 'inline event handler (onerror=, onload=, ontoggle=, ...)',
                'severity' => 4,
                'pattern' => '/\bon(?:error|load|click|dblclick|mouse(?:over|out|enter|leave|down|up|move)|'
                    .'focus|blur|input|change|submit|reset|select|key(?:down|up|press)|'
                    .'toggle|start|end|drag(?:start|end|over)?|drop|copy|cut|paste|contextmenu|'
                    .'scroll|resize|wheel|animation(?:start|end|iteration)|transitionend|'
                    .'pointer(?:down|up|move|over|out)|touch(?:start|end|move|cancel)|'
                    .'beforeunload|unload|hashchange|popstate|message|'
                    .'play|pause|ended|waiting|error|abort)\s*=\s*[\'"]?/i',
            ],
            [
                'id' => 'xss-data-uri-html',
                'category' => 'xss',
                'description' => 'data: URI carrying an HTML/JS payload (data:text/html, data:...base64 script smuggling)',
                'severity' => 4,
                'pattern' => '/data:(?:text\/html|application\/(?:xhtml\+xml|xml|javascript)|image\/svg\+xml)/i',
            ],
            [
                'id' => 'xss-javascript-uri',
                'category' => 'xss',
                'description' => 'javascript: / vbscript: URI scheme',
                'severity' => 4,
                'pattern' => '/\b(?:javascript|vbscript):/i',
            ],
            [
                'id' => 'xss-svg-onload',
                'category' => 'xss',
                'description' => '<svg onload=...> vector',
                'severity' => 4,
                'pattern' => '/<svg\b[^>]*onload/i',
            ],
            [
                'id' => 'xss-iframe-src',
                'category' => 'xss',
                'description' => '<iframe>/<embed>/<object> injection',
                'severity' => 3,
                'pattern' => '/<(?:iframe|embed|object)\b/i',
            ],
            [
                'id' => 'xss-document-cookie',
                'category' => 'xss',
                'description' => 'document.cookie / document.write exfiltration attempt',
                'severity' => 4,
                'pattern' => '/document\.(?:cookie|write|location)/i',
            ],
            [
                'id' => 'xss-html-entity-bypass',
                'category' => 'xss',
                'description' => 'encoded <script via HTML entities (&lt;script)',
                'severity' => 3,
                'pattern' => '/&(?:lt|#0*60|#x3c);\s*script/i',
            ],
        ];
    }
}
