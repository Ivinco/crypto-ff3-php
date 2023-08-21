<?php

/**
 * Same as str_pad but for multibyte strings, but without $pad_type support.
 *
 * @param string $string
 * @param int    $length
 * @param string $pad_string
 *
 * @return string
 */
function mb_str_pad(string $string, int $length, string $pad_string = " "): string
{
    return $string . str_repeat($pad_string, $length - mb_strlen($string));
}
