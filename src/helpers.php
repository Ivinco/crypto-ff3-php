<?php

/**
 * This file is part of https://github.com/Ivinco/crypto-ff3-php which is released under MIT.
 * See file LICENSE or go to https://github.com/Ivinco/crypto-ff3-php/blob/main/LICENSE for full license details.
 */

/**
 * Same as str_pad but for multibyte strings, but without $pad_type support.
 *
 * @param string $string
 * @param int    $length
 * @param string $pad_string
 *
 * @return string
 */

if(!function_exists('mb_str_pad')){
    function mb_str_pad(string $string, int $length, string $pad_string = " "): string
    {
        return $string . str_repeat($pad_string, $length - mb_strlen($string));
    }
}
