<?php

namespace Ivinco\Crypto;

use GMP;
use phpseclib3\Crypt\AES;

class FF3Cipher
{
    public const DOMAIN_MIN     = 1_000_000;
    public const BASE62         = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public const BASE62_LEN     = 62;
    public const RADIX_MAX      = 256;
    public const NUM_ROUNDS     = 8;
    public const BLOCK_SIZE     = 16;
    public const TWEAK_LEN      = 8;
    public const TWEAK_LEN_NEW  = 7;
    public const HALF_TWEAK_LEN = 4;

    private string  $tweak;
    private int     $radix;
    private ?string $alphabet;
    public float    $minLen;
    public float    $maxLen;
    private AES     $aesCipher;

    /**
     * @throws \Ivinco\Crypto\FF3Exception
     */
    public function __construct(string $key, string $tweak, int $radix = 10)
    {
        $keyBytes = hex2bin($key);

        $this->tweak = $tweak;
        $this->radix = $radix;

        if ($radix <= self::BASE62_LEN) {
            $this->alphabet = mb_substr(self::BASE62, 0, $radix, 'UTF-8');
        } else {
            $this->alphabet = null;
        }

        # Calculate range of supported message lengths [minLen..maxLen]
        # per revised spec, radix^minLength >= 1,000,000.
        $this->minLen = ceil(log(self::DOMAIN_MIN) / log($radix));

        # We simplify the specs log[radix](2^96) to 96/log2(radix) using the log base
        # change rule
        $this->maxLen = (2 * floor(log(2 ** 96) / log($radix)));

        # Check that key length is valid
        $keyLength = strlen($keyBytes);
        $keyLength = match (strlen($keyBytes)) {
            16      => 128,
            24      => 192,
            32      => 256,
            default => throw new FF3Exception("Invalid key length: $keyLength. Must be 128, 192, or 256 bits."),
        };

        if ($radix < 2 || $radix > self::RADIX_MAX) {
            throw new FF3Exception("Radix must be between 2 and " . self::RADIX_MAX . ", inclusive.");
        }

        if ($this->minLen < 2 || $this->maxLen < $this->minLen) {
            throw new FF3Exception("Invalid minLen or maxLen. Adjust your radix.");
        }

        $this->aesCipher = new AES('ecb');
        $this->aesCipher->setKeyLength($keyLength);
        $this->aesCipher->disablePadding();
        $this->aesCipher->setKey(strrev($keyBytes));
    }

    /**
     * @throws \Ivinco\Crypto\FF3Exception
     */
    public static function withCustomAlphabet(string $key, string $tweak, string $alphabet): self
    {
        $cipher           = new self($key, $tweak, mb_strlen($alphabet, 'UTF-8'));
        $cipher->alphabet = $alphabet;
        return $cipher;
    }

    /**
     * Encrypts the plaintext string and returns a ciphertext of the same length and format
     *
     * @throws \Ivinco\Crypto\FF3Exception
     */
    public function encrypt(string $plaintext): string
    {
        return $this->encryptWithTweak($plaintext, $this->tweak);
    }

    /**
     * @throws \Ivinco\Crypto\FF3Exception
     */
    public function decrypt(string $ciphertext): string
    {
        return $this->decryptWithTweak($ciphertext, $this->tweak);
    }

    /**
     * Encrypts the plaintext string and returns a ciphertext of the same length and format
     *
     * @throws \Ivinco\Crypto\FF3Exception
     */
    private function encryptWithTweak(string $plaintext, string $tweak): string
    {
        $tweakBytes = hex2bin($tweak);

        $n = mb_strlen($plaintext, 'UTF-8');

        // Check if message length is within minLength and maxLength bounds
        if ($n < $this->minLen || $n > $this->maxLen) {
            throw new FF3Exception("Message length $n is not within min $this->minLen and max $this->maxLen bounds.");
        }

        // Make sure the given the length of tweak in bits is 56 or 64
        $strlen = strlen($tweakBytes);
        if (!in_array($strlen, [self::TWEAK_LEN, self::TWEAK_LEN_NEW])) {
            throw new FF3Exception("Tweak length $strlen invalid: tweak must be 56 or 64 bits.");
        }

        // Calculate split point
        $u = (int) ceil($n / 2);
        $v = $n - $u;

        // Split the message
        $A = mb_substr($plaintext, 0, $u, 'UTF-8');
        $B = mb_substr($plaintext, $u, null, 'UTF-8');

        if (strlen($tweakBytes) === self::TWEAK_LEN_NEW) {
            # FF3-1
            $tweakBytes = hex2bin(self::decToHex($this->calculateTweak64FF31($tweakBytes)));
        }

        // Split the tweak
        $Tl = substr($tweakBytes, 0, self::HALF_TWEAK_LEN);
        $Tr = substr($tweakBytes, self::HALF_TWEAK_LEN, self::TWEAK_LEN);
        //error_log("Tweak: $tweak, tweakBytes:{" . bin2hex($tweakBytes) . "}");

        # Pre-calculate the modulus since it's only one of 2 values,
        # depending on whether it is even or odd
        $modU = gmp_pow($this->radix, $u);
        $modV = gmp_pow($this->radix, $v);
        //error_log("modU: $modU modV: $modV");

        # Main Feistel Round, 8 times
        #
        # AES ECB requires the number of bits in the plaintext to be a multiple of
        # the block size. Thus, we pad the input to 16 bytes
        for ($i = 0; $i < self::NUM_ROUNDS; $i++) {

            # Determine alternating Feistel round side
            if ($i % 2 === 0) {
                $m = $u;
                $W = $Tr;
            } else {
                $m = $v;
                $W = $Tl;
            }

            # P is fixed-length 16 bytes
            $P    = self::calculateP($i, $this->alphabet, $W, $B);
            $revP = self::decToHex(array_reverse($P));
            //error_log("P: " . self::decToHex($P) . ' revP: ' . $revP);

            // Calculate S by operating on P in place
            $S = $this->aesCipher->encrypt(hex2bin($revP));
            $S = strrev($S);
            //error_log("S:    " . bin2hex($S));

            $y = gmp_init('0x' . bin2hex($S), 16);

            # Calculate c
            $c = self::decodeIntR($A, $this->alphabet);
            $c = $c + $y;

            if ($i % 2 === 0) {
                $c = gmp_mod($c, $modU);
            } else {
                $c = gmp_mod($c, $modV);
            }

            $C = self::encodeIntR($c, $this->alphabet, $m);

            $A = $B;
            $B = $C;
            //error_log("A: {$A} B: {$B}");
        }

        return $A . $B;
    }

    /**
     * @throws \Ivinco\Crypto\FF3Exception
     */
    private function decryptWithTweak(string $ciphertext, string $tweak): string
    {
        $tweakBytes = hex2bin($tweak);

        $n = mb_strlen($ciphertext, 'UTF-8');

        // Check if message length is within minLength and maxLength bounds
        if ($n < $this->minLen || $n > $this->maxLen) {
            throw new FF3Exception("Message length $n is not within min $this->minLen and max $this->maxLen bounds.");
        }

        // Make sure the given the length of tweak in bits is 56 or 64
        $strlen = strlen($tweakBytes);
        if (!in_array($strlen, [self::TWEAK_LEN, self::TWEAK_LEN_NEW])) {
            throw new FF3Exception("Tweak length $strlen invalid: tweak must be 56 or 64 bits.");
        }

        // Calculate split point
        $u = ceil($n / 2);
        $v = $n - $u;

        // Split the message
        $A = mb_substr($ciphertext, 0, $u, 'UTF-8');
        $B = mb_substr($ciphertext, $u, null, 'UTF-8');

        if (strlen($tweakBytes) === self::TWEAK_LEN_NEW) {
            # FF3-1
            $tweakBytes = hex2bin(self::decToHex($this->calculateTweak64FF31($tweakBytes)));
        }

        // Split the tweak
        $Tl = substr($tweakBytes, 0, self::HALF_TWEAK_LEN);
        $Tr = substr($tweakBytes, self::HALF_TWEAK_LEN, self::TWEAK_LEN);
        //error_log("Tweak: $tweak, tweakBytes:{" . bin2hex($tweakBytes) . "}");

        # Pre-calculate the modulus since it's only one of 2 values,
        # depending on whether it is even or odd
        $modU = gmp_pow($this->radix, $u);
        $modV = gmp_pow($this->radix, $v);
        //error_log("modU: $modU modV: $modV");

        # Main Feistel Round, 8 times
        foreach (array_reverse(range(0, self::NUM_ROUNDS - 1)) as $i) {

            # Determine alternating Feistel round side
            if ($i % 2 === 0) {
                $m = $u;
                $W = $Tr;
            } else {
                $m = $v;
                $W = $Tl;
            }

            # P is fixed-length 16 bytes
            $P    = self::calculateP($i, $this->alphabet, $W, $A);
            $revP = self::decToHex(array_reverse($P));

            // Calculate S by operating on P in place
            $S = $this->aesCipher->encrypt(hex2bin($revP));
            $S = strrev($S);
            //error_log("S:    " . bin2hex($S));

            $y = gmp_init('0x' . bin2hex($S), 16);

            # Calculate c
            $c = self::decodeIntR($B, $this->alphabet);
            $c = $c - $y;

            if ($i % 2 === 0) {
                $c = gmp_mod($c, $modU);
            } else {
                $c = gmp_mod($c, $modV);
            }

            $C = self::encodeIntR($c, $this->alphabet, $m);

            $B = $A;
            $A = $C;
            //error_log("A: {$A} B: {$B}");
        }

        return $A . $B;
    }

    /**
     * Calculate the 64-bit tweak for FF3-1
     *
     * @param string $tweak56
     *
     * @return array
     */
    private function calculateTweak64FF31(string $tweak56): array
    {
        $tweak64 = array_fill(0, 8, 0);
        $tweak56 = array_values(unpack('C*', $tweak56));

        $tweak64[0] = $tweak56[0];
        $tweak64[1] = $tweak56[1];
        $tweak64[2] = $tweak56[2];
        $tweak64[3] = $tweak56[3] & 0xF0;
        $tweak64[4] = $tweak56[4];
        $tweak64[5] = $tweak56[5];
        $tweak64[6] = $tweak56[6];
        $tweak64[7] = ($tweak56[3] & 0x0F) << 4;

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
    public static function calculateP(int $i, string $alphabet, string $W, string $B): array
    {
        $P = array_fill(0, self::BLOCK_SIZE, 0);
        $W = array_values(unpack('C*', $W));

        $P[0] = $W[0];
        $P[1] = $W[1];
        $P[2] = $W[2];
        $P[3] = $W[3] ^ $i;

        // Decode string into number
        $BBytes = self::toBytes(self::decodeIntR($B, $alphabet));
        // Convert number to bytes (big endian)
        $BBytes = array_values(unpack('C*', $BBytes));

        // Copy BBytes to PBytes
        $startIndex = self::BLOCK_SIZE - count($BBytes);
        array_splice($P, $startIndex, count($BBytes), array_slice($BBytes, 0));

        return $P;
    }

    /**
     * Return a string representation of a number in the given base system for 2..62
     *
     * The string is left in a reversed order expected by the calling cryptographic
     * function
     *
     * @param \GMP   $n
     * @param string $alphabet
     * @param int    $length
     *
     * @return string
     * @throws \Ivinco\Crypto\FF3Exception
     * @example encodeIntR(10, hexdigits) -> 'A'
     */
    public static function encodeIntR(GMP $n, string $alphabet, int $length = 0): string
    {
        $base = mb_strlen($alphabet, 'UTF-8');

        if ($base > self::RADIX_MAX) {
            throw new FF3Exception("Base $base is outside range of supported radix 2.." . self::RADIX_MAX);
        }

        $alphabetArr = mb_str_split($alphabet, 1, 'UTF-8');

        $x = '';
        while (gmp_cmp($n, $base) >= 0) {
            [$n, $b] = gmp_div_qr($n, $base);
            $x .= $alphabetArr[gmp_intval($b)];
        }
        $x .= $alphabetArr[gmp_intval($n)];

        if (mb_strlen($x, 'UTF-8') < $length) {
            $x = mb_str_pad($x, $length, $alphabetArr[0]);
        }

        return $x;
    }

    /**
     * Decode a Base X encoded string into the number
     *
     * @param string $astring  The encoded string
     * @param string $alphabet The alphabet to use for decoding
     *
     * @return \GMP
     * @throws \Ivinco\Crypto\FF3Exception
     */
    public static function decodeIntR(string $astring, string $alphabet): GMP
    {
        $strlen = mb_strlen($astring, 'UTF-8');
        $base   = mb_strlen($alphabet, 'UTF-8');
        $num    = gmp_init(0);

        $idx = 0;
        foreach (array_reverse(mb_str_split($astring, 1, 'UTF-8')) as $char) {
            $power   = ($strlen - ($idx + 1));
            $charPos = mb_strpos($alphabet, $char, 0, 'UTF-8');
            if ($charPos === false) {
                throw new FF3Exception("char $char not found in alphabet $alphabet.");
            }
            $num += gmp_mul($charPos, gmp_pow($base, $power));
            $idx++;
        }

        return $num;
    }

    /**
     * Convert a GMP number to a byte string
     *
     * @param \GMP   $number
     * @param int    $length
     * @param string $byteorder
     *
     * @return string
     */
    public static function toBytes(GMP $number, int $length = 1, string $byteorder = 'big'): string
    {
        $binString    = gmp_export($number);
        $actualLength = strlen($binString);
        if ($actualLength < $length) {
            if ($byteorder === 'big') {
                $binString = str_repeat("\0", $length - $actualLength) . $binString;
            } else {
                $binString .= str_repeat("\0", $length - $actualLength);
            }
        }

        return $binString;
    }

    /**
     * Convert bytes to hex string
     *
     * @param array $values
     *
     * @return string
     */
    public static function decToHex(array $values): string
    {
        $hexString = "";
        foreach ($values as $value) {
            $hexString .= sprintf('%02x', $value);
        }
        return $hexString;
    }
}
