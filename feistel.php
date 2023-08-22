<?php

/**
 * This file is part of https://github.com/Ivinco/crypto-ff3-php which is released under MIT.
 * See file LICENSE or go to https://github.com/Ivinco/crypto-ff3-php/blob/main/LICENSE for full license details.
 */

function rev($str)
{
    return strrev($str);
}

function num_radix($str, $radix)
{
    return base_convert($str, $radix, 10);
}

function str_radix($number, $radix, $length)
{
    $converted = base_convert($number, 10, $radix);
    return str_pad($converted, $length, "0", STR_PAD_LEFT);
}

function xor_op($a, $b)
{
    return $a ^ $b;
}

function ciph($p)
{
    // Implement the CIPH function here.
    // For this example, I'll return the input as it is.
    return $p;
}

function feistel($X, $T, $radix)
{
    $n = strlen($X);
    $u = intval($n / 2);
    $v = $n - $u;
    $A = substr($X, 0, $u);
    $B = substr($X, $u);

    $TL = substr($T, 0, 32);
    $TR = substr($T, 32);

    for ($i = 0; $i <= 7; $i++) {
        if ($i % 2 == 0) {
            $m = $u;
            $W = $TR;
        } else {
            $m = $v;
            $W = $TL;
        }

        $P = rev(num_radix(rev($B), $radix) . "^12") . xor_op($W, rev(base_convert($i, 10, 4)));
        $Y = ciph($P);
        $y = num_radix(rev($Y), 2);
        $c = (num_radix(rev($A), $radix) + $y) % pow($radix, $m);
        $C = rev(str_radix($c, $radix, $m));

        $A = $B;
        $B = $C;
    }

    return $A . $B;
}

// Example usage
$X     = "123456";                           // Your input value
$T     = "abcdefghijklmnopqrstuvwxyz012345"; // Your T value, this should be 64 characters long
$radix = 10;                                 // Your radix value

$result = feistel($X, $T, $radix);
echo "Result: $result";
