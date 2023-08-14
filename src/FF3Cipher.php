<?php

namespace Ivinco\Crypto;

use phpseclib3\Crypt\AES;

class FF3Cipher
{
    public const DOMAIN_MIN     = 1000000;
    public const NUM_ROUNDS     = 8;
    public const BLOCK_SIZE     = 16;
    public const TWEAK_LEN      = 8;
    public const TWEAK_LEN_NEW  = 7;
    public const HALF_TWEAK_LEN = 4;
    public const MAX_RADIX      = 36;

    private mixed        $radix;
    private float        $minLen;
    private int|float    $maxLen;
    private string|false $tweakBytes;
    private string       $aesCipher;
    private string|false $keyBytes;

    /**
     * FF3Cipher constructor.
     *
     * @param string $key
     * @param string $tweak
     * @param int    $radix
     *
     * @throws \Ivinco\Crypto\FF3Excepotion
     */
    public function __construct(string $key, string $tweak, int $radix = 10)
    {
        $this->radix    = $radix;
        $this->keyBytes = hex2bin($key);
        $this->minLen   = ceil(log(self::DOMAIN_MIN) / log($radix));
        $this->maxLen   = (2 * floor(log(2 ** 96) / log($radix)));
        $keyLen         = strlen($this->keyBytes);

        $this->aesCipher = match ($keyLen) {
            16      => "aes-128-ecb",
            24      => "aes-192-ecb",
            32      => "aes-256-ecb",
            default => throw new FF3Excepotion("key length $keyLen but must be 128, 192, or 256 bits"),
        };

        if (($radix < 2) || ($radix > self::MAX_RADIX)) {
            throw new FF3Excepotion("radix must be between 2 and 36, inclusive");
        }

        if (($this->minLen < 2) || ($this->maxLen < $this->minLen)) {
            throw new FF3Excepotion("minLen or maxLen invalid, adjust your radix");
        }

        $this->tweakBytes = hex2bin($tweak);
        if (strlen($this->tweakBytes) === self::TWEAK_LEN_NEW) {
            $this->tweakBytes = self::calculateTweak64_FF3_1($this->tweakBytes);
        }
    }

    public static function mod($n, $m): int
    {
        return (($n % $m) + $m) % $m;
    }

    public static function calculateP($i, $radix, $w, $b): array|string
    {
        $p = str_repeat(chr(0), self::BLOCK_SIZE);

        $p[0] = $w[0];
        $p[1] = $w[1];
        $p[2] = $w[2];
        $p[3] = ($w[3] ^ $i);

        $b      = strrev($b);
        $big    = self::convertToBigInt($b, $radix);
        $bBytes = self::bigToUint8Array($big);

        return substr_replace($p, $bBytes, self::BLOCK_SIZE - strlen($bBytes));
    }

    public static function calculateTweak64_FF3_1($tweak56): string
    {
        $tweak64    = str_repeat(chr(0), 8);
        $tweak64[0] = $tweak56[0];
        $tweak64[1] = $tweak56[1];
        $tweak64[2] = $tweak56[2];
        $tweak64[3] = ($tweak56[3] & 0xF0);
        $tweak64[4] = $tweak56[4];
        $tweak64[5] = $tweak56[5];
        $tweak64[6] = $tweak56[6];
        $tweak64[7] = (($tweak56[3] & 0x0F) << 4);
        return $tweak64;
    }

    public static function reverseString($s): string
    {
        return strrev($s);
    }

    public static function convertToBigInt($value, $radix)
    {
        $big      = gmp_init(0, 10);
        $value    = strrev($value);
        $valueLen = strlen($value);

        for ($i = 0; $i < $valueLen; $i++) {
            $big = gmp_add(gmp_mul($big, $radix), base_convert($value[$i], $radix, 10));
        }

        return $big;
    }

    public static function bigToUint8Array($big): false|string
    {
        $hex = gmp_strval($big, 16);
        if (strlen($hex) % 2) {
            $hex = '0' . $hex;
        }
        return hex2bin($hex);
    }

    /**
     * Encrypts a plaintext string to a ciphertext string.
     *
     * @param string $plaintext
     *
     * @return string
     * @throws \Ivinco\Crypto\FF3Excepotion
     */
    public function encrypt(string $plaintext): string
    {
        $n = strlen($plaintext);

        if (($n < $this->minLen) || ($n > $this->maxLen)) {
            throw new FF3Excepotion("message length $n is not within min $this->minLen and max $this->maxLen bounds");
        }

        if ((strlen($this->tweakBytes) !== self::TWEAK_LEN) && (strlen($this->tweakBytes) !== self::TWEAK_LEN_NEW)) {
            throw new FF3Excepotion("tweak length " . strlen($this->tweakBytes) . " is invalid: tweak must be 56 or 64 bits");
        }

        $u = ceil($n / 2.0);
        $v = $n - $u;

        $a = substr($plaintext, 0, $u);
        $b = substr($plaintext, $u);

        $tl = substr($this->tweakBytes, 0, self::HALF_TWEAK_LEN);
        $tr = substr($this->tweakBytes, self::HALF_TWEAK_LEN, self::TWEAK_LEN);

        $modU = gmp_pow($this->radix, $u);
        $modV = gmp_pow($this->radix, $v);

        for ($i = 0; $i < self::NUM_ROUNDS; ++$i) {
            if ($i % 2 === 0) {
                $m = $u;
                $w = $tr;
            } else {
                $m = $v;
                $w = $tl;
            }

            $p = self::calculateP($i, $this->radix, $w, $b);
            $p = strrev($p);

            $s = openssl_encrypt($p, $this->aesCipher, $this->aesCipher, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
            $s = strrev($s);

            $y = gmp_init(bin2hex($s), 16);
            $c = gmp_add(self::convertToBigInt(strrev($a), $this->radix), $y);

            if ($i % 2 === 0) {
                $c = self::mod($c, $modU);
            } else {
                $c = self::mod($c, $modV);
            }

            $c = strrev(gmp_strval($c, $this->radix));
            $c .= substr("00000000", 0, $m - strlen($c));

            $a = $b;
            $b = $c;
        }

        return $a . $b;
    }

    /**
     * Decrypts a ciphertext string to a plaintext string.
     *
     * @param string $ciphertext
     *
     * @return string
     * @throws \Ivinco\Crypto\FF3Excepotion
     */
    public function decrypt(string $ciphertext): string
    {
        $n = strlen($ciphertext);

        if (($n < $this->minLen) || ($n > $this->maxLen)) {
            throw new FF3Excepotion("message length $n is not within min $this->minLen and max $this->maxLen bounds");
        }

        if ((strlen($this->tweakBytes) !== self::TWEAK_LEN) && (strlen($this->tweakBytes) !== self::TWEAK_LEN_NEW)) {
            throw new FF3Excepotion("tweak length " . strlen($this->tweakBytes) . " is invalid: tweak must be 56 or 64 bits");
        }

        $u = ceil($n / 2.0);
        $v = $n - $u;

        $a = substr($ciphertext, 0, $u);
        $b = substr($ciphertext, $u);

        $tl = substr($this->tweakBytes, 0, self::HALF_TWEAK_LEN);
        $tr = substr($this->tweakBytes, self::HALF_TWEAK_LEN, self::TWEAK_LEN);

        $modU = gmp_pow($this->radix, $u);
        $modV = gmp_pow($this->radix, $v);

        for ($i = (self::NUM_ROUNDS - 1); $i >= 0; --$i) {
            if ($i % 2 === 0) {
                $m = $u;
                $w = $tr;
            } else {
                $m = $v;
                $w = $tl;
            }

            $p = self::calculateP($i, $this->radix, $w, $a);
            $p = strrev($p);

            $s = openssl_encrypt($p, $this->aesCipher, $this->keyBytes, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
            $s = strrev($s);

            $y = gmp_init(bin2hex($s), 16);
            $c = gmp_sub(self::convertToBigInt(strrev($b), $this->radix), $y);

            if ($i % 2 === 0) {
                $c = self::mod($c, $modU);
            } else {
                $c = self::mod($c, $modV);
            }

            $c = strrev(gmp_strval($c, $this->radix));
            $c .= substr("00000000", 0, $m - strlen($c));

            $b = $a;
            $a = $c;
        }

        return $a . $b;
    }
}
