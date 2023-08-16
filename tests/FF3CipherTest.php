<?php

namespace Ivinco\Crypto\Tests;

use GMP;
use phpseclib3\Crypt\AES;
use Ivinco\Crypto\FF3Cipher;
use PHPUnit\Framework\TestCase;

class FF3CipherTest extends TestCase
{
    /**
     * Check that encryption and decryption works as expected
     *
     * @return void
     */
    public function testAesEcb(): void
    {
        // NIST test vector for ECB-AES128
        $key = hex2bin('2b7e151628aed2a6abf7158809cf4f3c');
        $pt  = hex2bin('6bc1bee22e409f96e93d7e117393172a');

        $cipher = new AES('ecb');
        $cipher->setKey($key);
        $cipher->disablePadding();
        $ct = $cipher->encrypt($pt);

        $this->assertEquals('3ad77bb40d7a3660a89ecaf32466ef97', bin2hex($ct));
    }

    //    protected static function testVectorsProvider(): array
    //    {
    //        return [
    //            # AES-128
    //            [
    //                "radix"      => 10,
    //                "key"        => "EF4359D8D580AA4F7F036D6F04FC6A94",
    //                "tweak"      => "D8E7920AFA330A73",
    //                "plaintext"  => "890121234567890000",
    //                "ciphertext" => "750918814058654607",
    //            ],
    //            [
    //                "radix"      => 10,
    //                "key"        => "EF4359D8D580AA4F7F036D6F04FC6A94",
    //                "tweak"      => "9A768A92F60E12D8",
    //                "plaintext"  => "890121234567890000",
    //                "ciphertext" => "018989839189395384",
    //            ],
    //            [
    //                "radix"      => 10,
    //                "key"        => "EF4359D8D580AA4F7F036D6F04FC6A94",
    //                "tweak"      => "D8E7920AFA330A73",
    //                "plaintext"  => "89012123456789000000789000000",
    //                "ciphertext" => "48598367162252569629397416226",
    //            ],
    //            [
    //                "radix"      => 10,
    //                "key"        => "EF4359D8D580AA4F7F036D6F04FC6A94",
    //                "tweak"      => "0000000000000000",
    //                "plaintext"  => "89012123456789000000789000000",
    //                "ciphertext" => "34695224821734535122613701434",
    //            ],
    //            [
    //                "radix"      => 26,
    //                "key"        => "EF4359D8D580AA4F7F036D6F04FC6A94",
    //                "tweak"      => "9A768A92F60E12D8",
    //                "plaintext"  => "0123456789abcdefghi",
    //                "ciphertext" => "g2pk40i992fn20cjakb",
    //            ],
    //        ];
    //    }

    public static function encodeIntRProvider(): array
    {
        return [
            [5, "01", "101"],
            [6, "01234", "11"],
            [7, "01234", "00012", 5],
            [7, "abcde", "aaabc", 5],
            [10, "0123456789abcdef", "a"],
            [32, "0123456789abcdef", "20"],
        ];
    }

    /**
     * Test encoding of integer to string
     *
     * @param int    $n
     * @param string $alphabet
     * @param string $expected
     * @param int    $length
     *
     * @return void
     * @throws \Ivinco\Crypto\FF3Exception
     * @dataProvider encodeIntRProvider
     */
    public function testEncodeIntR(int $n, string $alphabet, string $expected, int $length = 0): void
    {
        $this->assertEquals($expected, FF3Cipher::encodeIntR($n, $alphabet, $length));
    }

    public static function decodeIntRProvider(): array
    {
        return [
            ["123", "0123456789", new GMP(321)],
            ["101", "0123456789", new GMP(101)],
            ["20", "0123456789abcdef", new GMP(0x02)],
            ["aa", "0123456789abcdef", new GMP(0xAA)],
        ];
    }

    /**
     * Test decoding of integer from string
     *
     * @param string $string
     * @param string $alphabet
     * @param \GMP   $expected
     *
     * @return void
     * @throws \Ivinco\Crypto\FF3Exception
     * @dataProvider decodeIntRProvider
     */
    public function testDecodeIntR(string $string, string $alphabet, GMP $expected): void
    {
        $this->assertEquals($expected, FF3Cipher::decodeIntR($string, $alphabet));
    }

    /**
     * @return void
     * @throws \Ivinco\Crypto\FF3Exception
     */
    public function testCalculateP(): void
    {
        $i        = 0;
        $alphabet = '0123456789';
        $b        = '567890000';
        $w        = hex2bin('FA330A73');

        $p = FF3Cipher::calculateP($i, $alphabet, $w, $b);

        $expected = hex2bin('FA330A730000000000000000000181cd');
        $expected = array_values(unpack('C*', $expected));

        $this->assertEquals($expected, $p);
    }

    /**
     * @return void
     * @throws \Ivinco\Crypto\FF3Exception
     */
    public function testEncryptBoundaries(): void
    {
        $cipher = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A94", "D8E7920AFA330A73");

        // test max length 56 digit string with default radix 10
        $plaintext  = "12345678901234567890123456789012345678901234567890123456";
        $ciphertext = $cipher->encrypt($plaintext);
        $decrypted  = $cipher->decrypt($ciphertext);
        $this->assertEquals($plaintext, $decrypted);

//        // test max length 40 alphanumeric string with radix 26
//        $cipher     = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A94", "D8E7920AFA330A73", 26);
//        $plaintext  = "0123456789abcdefghijklmn";
//        $ciphertext = $cipher->encrypt($plaintext);
//        $decrypted  = $cipher->decrypt($ciphertext);
//        $this->assertEquals($plaintext, $decrypted);
//
//        // test max length 36 alphanumeric string with radix 36
//        $cipher     = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A94", "D8E7920AFA330A73", 36);
//        $plaintext  = "abcdefghijklmnopqrstuvwxyz0123456789";
//        $ciphertext = $cipher->encrypt($plaintext);
//        $decrypted  = $cipher->decrypt($ciphertext);
//        $this->assertEquals($plaintext, $decrypted);
    }
}
