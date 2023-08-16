<?php

namespace Ivinco\Crypto;

namespace Ivinco\Crypto;

use Exception;
use phpseclib3\Crypt\AES;

class FF3Cipher
{
    public const DOMAIN_MIN     = 1000000;
    public const RADIX_MAX      = 256;
    public const BASE62         = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public const BASE62_LEN     = 62;
    public const NUM_ROUNDS     = 8;
    public const BLOCK_SIZE     = 16;
    public const TWEAK_LEN      = 8;
    public const TWEAK_LEN_NEW  = 7;
    public const HALF_TWEAK_LEN = 4;

    private        $key;
    private string $tweak;
    private        $radix;
    private        $alphabet;
    private        $minLen;
    private        $maxLen;
    private        $aesCipher;

    /**
     * @throws \Ivinco\Crypto\FF3Exception
     */
    public function __construct(string $key, string $tweak, int $radix = 10)
    {
        $this->key   = hex2bin($key);
        $this->tweak = $tweak;
        $this->radix = $radix;

        if ($radix <= self::BASE62_LEN) {
            $this->alphabet = substr(self::BASE62, 0, $radix);
        } else {
            $this->alphabet = null;
        }

        $this->minLen = (int) ceil(log(self::DOMAIN_MIN) / log($radix));
        $this->maxLen = 2 * (int) floor(96 / log($radix, 2));

        $keyLength = strlen($this->key);

        if (!in_array($keyLength, [16, 24, 32])) {
            throw new FF3Exception("Invalid key length: $keyLength. Must be 128, 192, or 256 bits.");
        }

        if ($radix < 2 || $radix > self::RADIX_MAX) {
            throw new FF3Exception("Radix must be between 2 and " . self::RADIX_MAX);
        }

        if ($this->minLen < 2 || $this->maxLen < $this->minLen) {
            throw new FF3Exception("Invalid minLen or maxLen. Adjust your radix.");
        }

        $this->aesCipher = new AES('ECB');
        $this->aesCipher->setKey(strrev($this->key));
    }

    public static function withCustomAlphabet($key, string $tweak, $alphabet): self
    {
        $cipher           = new self($key, $tweak, strlen($alphabet));
        $cipher->alphabet = $alphabet;
        return $cipher;
    }

    /**
     * @throws \Ivinco\Crypto\FF3Exception
     */
    public function encrypt($plaintext): string
    {
        return $this->encryptWithTweak($plaintext, $this->tweak);
    }

    /**
     * @throws \Ivinco\Crypto\FF3Exception
     */
    public function decrypt($ciphertext): string
    {
        return $this->decryptWithTweak($ciphertext, $this->tweak);
    }

    /**
     * @throws \Ivinco\Crypto\FF3Exception
     */
    private function encryptWithTweak($plaintext, string $tweak): string
    {
        $tweakBytes = hex2bin($tweak);

        $n = strlen($plaintext);

        if ($n < $this->minLen || $n > $this->maxLen) {
            throw new FF3Exception("Message length $n is not within min $this->minLen and max $this->maxLen bounds");
        }

        if (!in_array(strlen($tweakBytes), [self::TWEAK_LEN, self::TWEAK_LEN_NEW])) {
            throw new FF3Exception("Invalid tweak length");
        }

        $u = (int) ceil($n / 2);
        $v = $n - $u;
        $A = substr($plaintext, 0, $u);
        $B = substr($plaintext, $u);

        if (strlen($tweakBytes) === self::TWEAK_LEN_NEW) {
            $tweakBytes = $this->calculateTweak64FF31($tweakBytes);
        }

        $Tl = substr($tweakBytes, 0, self::HALF_TWEAK_LEN);
        $Tr = substr($tweakBytes, self::HALF_TWEAK_LEN);

        $modU = gmp_pow($this->radix, $u);
        $modV = gmp_pow($this->radix, $v);

        for ($i = 0; $i < self::NUM_ROUNDS; $i++) {
            if ($i % 2 === 0) {
                $m = $u;
                $W = $Tr;
            } else {
                $m = $v;
                $W = $Tl;
            }

            $P    = pack('C*', self::calculateP($i, $this->alphabet, $W, $B));
            $revP = strrev($P);

            $S = $this->aesCipher->encrypt($revP);
            $S = strrev($S);

            $y = gmp_intval(gmp_init(bin2hex($S), 16));

            $c = self::decodeIntR($A, $this->alphabet) + $y;

            if ($i % 2 === 0) {
                $cGmp = gmp_mod($c, $modU);
            } else {
                $cGmp = gmp_mod($c, $modV);
            }
            $c = gmp_intval($cGmp);

            $C = self::encodeIntR($c, $this->alphabet, $m);

            $A = $B;
            $B = $C;
        }

        return $A . $B;
    }

    /**
     * @throws \Ivinco\Crypto\FF3Exception
     */
    private function decryptWithTweak($ciphertext, string $tweak): string
    {
        $tweakBytes = hex2bin($tweak);

        $n = strlen($ciphertext);

        if ($n < $this->minLen || $n > $this->maxLen) {
            throw new FF3Exception("Message length $n is not within min $this->minLen and max $this->maxLen bounds");
        }

        if (!in_array(strlen($tweakBytes), [self::TWEAK_LEN, self::TWEAK_LEN_NEW])) {
            throw new FF3Exception("Invalid tweak length");
        }

        $u = (int) ceil($n / 2);
        $v = $n - $u;
        $A = substr($ciphertext, 0, $u);
        $B = substr($ciphertext, $u);

        if (strlen($tweakBytes) === self::TWEAK_LEN_NEW) {
            $tweakBytes = $this->calculateTweak64FF31($tweakBytes);
        }

        $Tl = substr($tweakBytes, 0, self::HALF_TWEAK_LEN);
        $Tr = substr($tweakBytes, self::HALF_TWEAK_LEN);

        $modU = gmp_pow($this->radix, $u);
        $modV = gmp_pow($this->radix, $v);

        for ($i = self::NUM_ROUNDS - 1; $i >= 0; $i--) {
            if ($i % 2 === 0) {
                $m = $u;
                $W = $Tr;
            } else {
                $m = $v;
                $W = $Tl;
            }

            $P    = pack('C*', self::calculateP($i, $this->alphabet, $W, $A)); // switched from B to A
            $revP = strrev($P);

            $S = $this->aesCipher->encrypt($revP);
            $S = strrev($S);

            $y = gmp_intval(gmp_init(bin2hex($S), 16));

            $c = self::decodeIntR($B, $this->alphabet) - $y; // switched from A to B and changed addition to subtraction

            if ($i % 2 === 0) {
                $cGmp = gmp_mod($c, $modU);
            } else {
                $cGmp = gmp_mod($c, $modV);
            }
            $c = gmp_intval($cGmp);

            $C = self::encodeIntR($c, $this->alphabet, $m);

            $B = $A; // swapped A and B assignments
            $A = $C;
        }

        return $B . $A; // switched order of A and B
    }

    /**
     * Calculate the 64-bit tweak for FF3-1
     *
     * @param string $tweak56
     *
     * @return string
     */
    private function calculateTweak64FF31(string $tweak56): string
    {
        $tweak64 = str_repeat(chr(0), 8);

        $tweak64[0] = $tweak56[0];
        $tweak64[1] = $tweak56[1];
        $tweak64[2] = $tweak56[2];
        $tweak64[3] = $tweak56[3] & chr(0xF0);
        $tweak64[4] = $tweak56[4];
        $tweak64[5] = $tweak56[5];
        $tweak64[6] = $tweak56[6];
        $tweak64[7] = ($tweak56[3] & chr(0x0F)) << 4;

        return $tweak64;
    }

    /**
     * Calculate the P value for the given round
     *
     * @param int    $i
     * @param string $alphabet
     * @param string $W
     * @param string $B
     *
     * @return array
     * @throws \Ivinco\Crypto\FF3Exception
     */
    public static function calculateP($i, string $alphabet, $W, $B): array
    {
        $P = array_fill(0, self::BLOCK_SIZE, 0);
        $W = unpack('C*', $W);

        $P[0] = $W[1];
        $P[1] = $W[2];
        $P[2] = $W[3];
        $P[3] = $W[4] ^ (int) $i;

        // Decode string into number
        $BDecoded = gmp_strval(self::decodeIntR($B, $alphabet));

        // Convert number to bytes (big endian)
        $BBytes = str_pad(pack('J', $BDecoded), 12, chr(0), STR_PAD_LEFT);
        $BBytes = array_values(unpack('C*', $BBytes));

        $BBytesLen = count($BBytes);
        for ($j = 0; $j < $BBytesLen; $j++) {
            $P[self::BLOCK_SIZE - $j - 1] = $BBytes[$BBytesLen - $j - 1];
        }

        return $P;
    }

    /**
     * Return a string representation of a number in the given base system for 2..62
     *
     * The string is left in a reversed order expected by the calling cryptographic
     * function
     *
     * @param int    $n
     * @param string $alphabet
     * @param int    $length
     *
     * @return string
     * @throws \Ivinco\Crypto\FF3Exception
     * @example encodeIntR(10, hexdigits) -> 'A'
     */
    public static function encodeIntR(int $n, string $alphabet, int $length = 0): string
    {
        $base = strlen($alphabet);

        if ($base > self::RADIX_MAX) {
            throw new FF3Exception("Base $base is outside range of supported radix 2.." . self::RADIX_MAX);
        }

        $x = '';
        while ($n >= $base) {
            $b = gmp_intval(gmp_mod($n, $base));
            $n = gmp_intval(gmp_div($n, $base));
            //echo "n: $n, base: $base, b: $b\n";
            $x = $alphabet[$b] . $x;
        }

        $x = $alphabet[$n] . $x;

        if (strlen($x) < $length) {
            $x = str_pad($x, $length, $alphabet[0], STR_PAD_LEFT);
        }

        return $x;
    }

    /**
     * Decode a Base X encoded string into the number
     *
     * @param string $string   The encoded string
     * @param string $alphabet The alphabet to use for decoding
     *
     * @return \GMP
     * @throws \Ivinco\Crypto\FF3Exception
     */
    public static function decodeIntR(string $string, string $alphabet): \GMP
    {
        $strlen = strlen($string);
        $base   = strlen($alphabet);
        $num    = gmp_init(0);

        $idx = 0;
        foreach (str_split(strrev($string)) as $char) {
            $power   = ($strlen - ($idx + 1));
            $charIdx = strpos($alphabet, $char);
            if ($charIdx === false) {
                throw new FF3Exception("Char $char not found in alphabet $alphabet");
            }

            $num += gmp_mul($charIdx, gmp_pow($base, $power));
            $idx++;
        }

        return $num;
    }
}
