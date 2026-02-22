<?php
declare(strict_types=1);

function clean_input(string $value): string
{
    return trim($value);
}

function escape_output(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
