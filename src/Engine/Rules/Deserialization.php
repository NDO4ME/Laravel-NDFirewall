<?php

namespace NDFirewall\Engine\Rules;

class Deserialization
{
    public static function rules(): array
    {
        return [
            [
                'id' => 'deser-php-object-injection',
                'category' => 'deserialization',
                'description' => 'PHP serialized object signature in user input (potential PHP Object Injection)',
                'severity' => 5,
                'pattern' => '/[oOcC]:\d+:"[^"]+":\d+:\{/',
            ],
            [
                'id' => 'deser-phar-upload',
                'category' => 'deserialization',
                'description' => 'PHAR file magic bytes / phar:// deserialization gadget chain trigger',
                'severity' => 4,
                'pattern' => '/GBMB$|__HALT_COMPILER\s*\(\s*\)\s*;/i',
            ],
            [
                'id' => 'deser-laravel-signed-tamper',
                'category' => 'deserialization',
                'description' => 'raw serialized array passed where Laravel expects a scalar (possible mass-assignment/gadget probe)',
                'severity' => 3,
                'pattern' => '/^a:\d+:\{/',
            ],
        ];
    }
}
