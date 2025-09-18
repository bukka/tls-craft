<?php

$finder = PhpCsFixer\Finder::create()
    ->in([__DIR__.'/src', __DIR__.'/tests'])
    ->name('*.php')
    ->ignoreDotFiles(true)
    ->ignoreVCS(true);

return (new PhpCsFixer\Config())
    // Symfony preset
    ->setRules([
        '@Symfony' => true,
        '@Symfony:risky' => true,
        '@PSR12' => true,
        'declare_strict_types' => false,
        'ordered_imports' => ['imports_order' => ['class', 'function', 'const'], 'sort_algorithm' => 'alpha'],
        'phpdoc_align' => ['align' => 'vertical'],
        'phpdoc_summary' => false,
        'native_function_invocation' => false,
        'no_superfluous_phpdoc_tags' => ['allow_mixed' => true, 'remove_inheritdoc' => true],
        'single_quote' => true,
        'yoda_style' => false,
        'method_argument_space' => [
            'on_multiline' => 'ensure_fully_multiline', // each arg on its own line
            'keep_multiple_spaces_after_comma' => false // avoid weird spacing after commas
        ],
        'trailing_comma_in_multiline' => ['elements' => ['parameters', 'arguments', 'arrays']],
        'binary_operator_spaces' => [
            'default' => 'single_space',
            'operators' => [
                '='  => 'single_space',
                '=>' => 'single_space', // set to 'align_single_space_minimal' if you like aligning array arrows
            ],
        ],
        'multiline_whitespace_before_semicolons' => ['strategy' => 'no_multi_line'],
        'global_namespace_import' => ['import_classes' => true, 'import_constants' => true, 'import_functions' => true],
        'modernize_strpos' => true,
        'nullable_type_declaration_for_default_null_value' => true,
    ])
    ->setRiskyAllowed(true)
    ->setFinder($finder)
    ->setCacheFile(__DIR__.'/.php-cs-fixer.cache');
