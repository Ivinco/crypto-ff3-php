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

    public static function vectorsProvider(): array
    {
        return [
            # AES-128
            [
                "radix"      => 10,
                "key"        => "EF4359D8D580AA4F7F036D6F04FC6A94",
                "tweak"      => "D8E7920AFA330A73",
                "plaintext"  => "890121234567890000",
                "ciphertext" => "750918814058654607",
            ],
            [
                "radix"      => 10,
                "key"        => "EF4359D8D580AA4F7F036D6F04FC6A94",
                "tweak"      => "9A768A92F60E12D8",
                "plaintext"  => "890121234567890000",
                "ciphertext" => "018989839189395384",
            ],
            [
                "radix"      => 10,
                "key"        => "EF4359D8D580AA4F7F036D6F04FC6A94",
                "tweak"      => "D8E7920AFA330A73",
                "plaintext"  => "89012123456789000000789000000",
                "ciphertext" => "48598367162252569629397416226",
            ],
            [
                "radix"      => 10,
                "key"        => "EF4359D8D580AA4F7F036D6F04FC6A94",
                "tweak"      => "0000000000000000",
                "plaintext"  => "89012123456789000000789000000",
                "ciphertext" => "34695224821734535122613701434",
            ],
            [
                "radix"      => 26,
                "key"        => "EF4359D8D580AA4F7F036D6F04FC6A94",
                "tweak"      => "9A768A92F60E12D8",
                "plaintext"  => "0123456789abcdefghi",
                "ciphertext" => "g2pk40i992fn20cjakb",
            ],

            # AES - 192
            [
                "radix"      => 10,
                "key"        => "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6",
                "tweak"      => "D8E7920AFA330A73",
                "plaintext"  => "890121234567890000",
                "ciphertext" => "646965393875028755",
            ],
            [
                "radix"      => 10,
                "key"        => "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6",
                "tweak"      => "9A768A92F60E12D8",
                "plaintext"  => "890121234567890000",
                "ciphertext" => "961610514491424446",
            ],
            [
                "radix"      => 10,
                "key"        => "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6",
                "tweak"      => "D8E7920AFA330A73",
                "plaintext"  => "89012123456789000000789000000",
                "ciphertext" => "53048884065350204541786380807",
            ],
            [
                "radix"      => 10,
                "key"        => "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6",
                "tweak"      => "0000000000000000",
                "plaintext"  => "89012123456789000000789000000",
                "ciphertext" => "98083802678820389295041483512",
            ],
            [
                "radix"      => 26,
                "key"        => "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6",
                "tweak"      => "9A768A92F60E12D8",
                "plaintext"  => "0123456789abcdefghi",
                "ciphertext" => "i0ihe2jfj7a9opf9p88",
            ],

            # AES - 256
            [
                "radix"      => 10,
                "key"        => "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C",
                "tweak"      => "D8E7920AFA330A73",
                "plaintext"  => "890121234567890000",
                "ciphertext" => "922011205562777495",
            ],
            [
                "radix"      => 10,
                "key"        => "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C",
                "tweak"      => "9A768A92F60E12D8",
                "plaintext"  => "890121234567890000",
                "ciphertext" => "504149865578056140",
            ],
            [
                "radix"      => 10,
                "key"        => "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C",
                "tweak"      => "D8E7920AFA330A73",
                "plaintext"  => "89012123456789000000789000000",
                "ciphertext" => "04344343235792599165734622699",
            ],
            [
                "radix"      => 10,
                "key"        => "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C",
                "tweak"      => "0000000000000000",
                "plaintext"  => "89012123456789000000789000000",
                "ciphertext" => "30859239999374053872365555822",
            ],
            [
                "radix"      => 26,
                "key"        => "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C",
                "tweak"      => "9A768A92F60E12D8",
                "plaintext"  => "0123456789abcdefghi",
                "ciphertext" => "p0b2godfja9bhb7bk38",
            ],
        ];
    }

    public static function vectorsACVPAESFF31Provider()
    {
        return [
            # AES - 128
            [
                # tg: 1 tc: 1
                "radix"      => 10,
                "alphabet"   => "0123456789",
                "key"        => "2DE79D232DF5585D68CE47882AE256D6",
                "tweak"      => "CBD09280979564",
                "plaintext"  => "3992520240",
                "ciphertext" => "8901801106",
            ],
            [
                # tg: 1 tc: 1
                "radix"      => 10,
                "alphabet"   => "0123456789",
                "key"        => "01C63017111438F7FC8E24EB16C71AB5",
                "tweak"      => "C4E822DCD09F27",
                "plaintext"  => "60761757463116869318437658042297305934914824457484538562",
                "ciphertext" => "35637144092473838892796702739628394376915177448290847293",
            ],
            [
                # tg: 2 tc: 26
                "radix"      => 26,
                "alphabet"   => "abcdefghijklmnopqrstuvwxyz",
                "key"        => "718385E6542534604419E83CE387A437",
                "tweak"      => "B6F35084FA90E1",
                "plaintext"  => "wfmwlrorcd",
                "ciphertext" => "ywowehycyd",
            ],
            [
                # tg: 2 tc: 27
                "radix"      => 26,
                "alphabet"   => "abcdefghijklmnopqrstuvwxyz",
                "key"        => "DB602DFF22ED7E84C8D8C865A941A238",
                "tweak"      => "EBEFD63BCC2083",
                "plaintext"  => "kkuomenbzqvggfbteqdyanwpmhzdmoicekiihkrm",
                "ciphertext" => "belcfahcwwytwrckieymthabgjjfkxtxauipmjja",
            ],
            [
                # tg: 3 tc: 51
                "radix"      => 64,
                "alphabet"   => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/",
                "key"        => "AEE87D0D485B3AFD12BD1E0B9D03D50D",
                "tweak"      => "5F9140601D224B",
                "plaintext"  => "ixvuuIHr0e",
                "ciphertext" => "GR90R1q838",
            ],
            [
                # tg: 3 tc: 52
                "radix"      => 64,
                "alphabet"   => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/",
                "key"        => "7B6C88324732F7F4AD435DA9AD77F917",
                "tweak"      => "3F42102C0BAB39",
                "plaintext"  => "21q1kbbIVSrAFtdFWzdMeIDpRqpo",
                "ciphertext" => "cvQ/4aGUV4wRnyO3CHmgEKW5hk8H",
            ],

            # AES - 192
            [
                # tg: 4 tc: 76
                "radix"      => 10,
                "alphabet"   => "0123456789",
                "key"        => "F62EDB777A671075D47563F3A1E9AC797AA706A2D8E02FC8",
                "tweak"      => "493B8451BF6716",
                "plaintext"  => "4406616808",
                "ciphertext" => "1807744762",
            ],
            [
                # tg: 4 tc: 77
                "radix"      => 10,
                "alphabet"   => "0123456789",
                "key"        => "0951B475D1A327C52756F2624AF224C80E9BE85F09B2D44F",
                "tweak"      => "D679E2EA3054E1",
                "plaintext"  => "99980459818278359406199791971849884432821321826358606310",
                "ciphertext" => "84359031857952748660483617398396641079558152339419110919",
            ],
            [
                # tg: 5 tc: 101
                "radix"      => 26,
                "alphabet"   => "abcdefghijklmnopqrstuvwxyz",
                "key"        => "49CCB8F62D941E5684599ECA0300937B5C766D053E109777",
                "tweak"      => "0BFCF75CDC2FC1",
                "plaintext"  => "jaxlrchjjx",
                "ciphertext" => "kjdbfqyahd",
            ],
            [
                # tg: 5 tc: 102
                "radix"      => 26,
                "alphabet"   => "abcdefghijklmnopqrstuvwxyz",
                "key"        => "03D253674A9309FF07ED0E71B24CBFE769025E09FCE544D7",
                "tweak"      => "B33176B1DA0F6C",
                "plaintext"  => "tafzrybuvhiqvcyztuxfnwfprmqlwpayphxbawpl",
                "ciphertext" => "loaemzbgqkywkdhmncrijzildzleoqibtthdiliv",
            ],
            [
                # tg: 6 tc: 126
                "radix"      => 64,
                "alphabet"   => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/",
                "key"        => "1C24B74B7C1B9969314CB53E92F98EFD620D5520017FB076",
                "tweak"      => "0380341C425A6F",
                "plaintext"  => "6np8r2t8zo",
                "ciphertext" => "HgpCXoA1Rt",
            ],
            [
                # tg: 6 tc: 127
                "radix"      => 64,
                "alphabet"   => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/",
                "key"        => "C0ABADFC071379824A070E8C3FD40DD9BFD7A3C99A0D5FE3",
                "tweak"      => "6C2926C705DDAF",
                "plaintext"  => "GKB6sa9g56BSJ09iJ4dsaxRdsMvo",
                "ciphertext" => "gC0tTSdDPxM79QOWi+z+SNL9C4V+",
            ],

            # AES - 256
            [
                # tg: 7 tc: 151
                "radix"      => 10,
                "alphabet"   => "0123456789",
                "key"        => "1FAA03EFF55A06F8FAB3F1DC57127D493E2F8F5C365540467A3A055BDBE6481D",
                "tweak"      => "4D67130C030445",
                "plaintext"  => "3679409436",
                "ciphertext" => "1735794859",
            ],
            [
                # tg: 7 tc: 152
                "radix"      => 10,
                "alphabet"   => "0123456789",
                "key"        => "9CE16E125BD422A011408EB083355E7089E70A4CD2F59E141D0B94A74BCC5967",
                "tweak"      => "4684635BD2C821",
                "plaintext"  => "85783290820098255530464619643265070052870796363685134012",
                "ciphertext" => "75104723514036464144839960480545848044718729603261409917",
            ],
            [
                # tg: 8 tc: 176
                "radix"      => 26,
                "alphabet"   => "abcdefghijklmnopqrstuvwxyz",
                "key"        => "6187F8BDE99F7DAF9E3EE8A8654308E7E51D31FA88AFFAEB5592041C033B736B",
                "tweak"      => "5820812B3D5DD1",
                "plaintext"  => "mkblaoiyfd",
                "ciphertext" => "ifpyiihvvq",
            ],
            [
                # tg: 8 tc: 177
                "radix"      => 26,
                "alphabet"   => "abcdefghijklmnopqrstuvwxyz",
                "key"        => "F6807FB9688937E4D4956006C8F0CB2394148A5F4B14666CF353F4941428FFD7",
                "tweak"      => "30C87B99890096",
                "plaintext"  => "wrammvhudopmaazlsxevzwzwpezzmghwfnmkitnk",
                "ciphertext" => "nzftnfkliuctlmtdfrxfhwgevrbcbgljurnytxkj",
            ],
            [
                # tg: 9 tc: 201
                "radix"      => 64,
                "alphabet"   => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/",
                "key"        => "9C2B69F7DDF181C54398E345BE04C2F6B00B9DD1679200E1E04C4FF961AE0F09",
                "tweak"      => "103C238B4B1E44",
                "plaintext"  => "H2/c6FblSA",
                "ciphertext" => "EOg4H1bE+8",
            ],
            [
                # tg: 9 tc: 202
                "radix"      => 64,
                "alphabet"   => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/",
                "key"        => "C58BCBD08B90006CEC7E82B2D987D79F6A21111DEF0CEBB273CBAEB2D6CD4044",
                "tweak"      => "7036604882667B",
                "plaintext"  => "bz5TcS1krnD8IOLdrQeKzXkLAa6h",
                "ciphertext" => "Z6x3/9LPW8SZunRezRM8J68Q4J03",
            ],
        ];
    }

    public static function encodeIntRProvider(): array
    {
        return [
            [gmp_init(5), "01", "101"],
            [gmp_init(6), "01234", "11"],
            [gmp_init(7), "01234", "00012", 5],
            [gmp_init(7), "abcde", "aaabc", 5],
            [gmp_init(10), "0123456789abcdef", "a"],
            [gmp_init(32), "0123456789abcdef", "20"],
        ];
    }

    /**
     * Test encoding of integer to string
     *
     * @param \GMP   $n
     * @param string $alphabet
     * @param string $expected
     * @param int    $length
     *
     * @return void
     * @throws \Ivinco\Crypto\FF3Exception
     * @dataProvider encodeIntRProvider
     */
    public function testEncodeIntR(GMP $n, string $alphabet, string $expected, int $length = 0): void
    {
        $this->assertEquals($expected, strrev(FF3Cipher::encodeIntR($n, $alphabet, $length)));
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
        // test max length 56 digit string with default radix 10
        $cipher     = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A94", "D8E7920AFA330A73");
        $plaintext  = "12345678901234567890123456789012345678901234567890123456";
        $encrypted  = "76239557710184799016672488626962231166888602835724035798";
        $ciphertext = $cipher->encrypt($plaintext);
        $this->assertEquals($encrypted, $ciphertext);
        $decrypted = $cipher->decrypt($encrypted);
        $this->assertEquals($plaintext, $decrypted);

        // test max length 40 alphanumeric string with radix 26
        $cipher     = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A94", "D8E7920AFA330A73", 26);
        $plaintext  = "0123456789abcdefghijklmn";
        $ciphertext = $cipher->encrypt($plaintext);
        $decrypted  = $cipher->decrypt($ciphertext);
        $this->assertEquals($plaintext, $decrypted);

        // test max length 36 alphanumeric string with radix 36
        $cipher     = new FF3Cipher("EF4359D8D580AA4F7F036D6F04FC6A94", "D8E7920AFA330A73", 36);
        $plaintext  = "abcdefghijklmnopqrstuvwxyz0123456789";
        $ciphertext = $cipher->encrypt($plaintext);
        $decrypted  = $cipher->decrypt($ciphertext);
        $this->assertEquals($plaintext, $decrypted);
    }

    /**
     * @return void
     * @throws \Ivinco\Crypto\FF3Exception
     * @throws \JsonException
     * @dataProvider vectorsProvider
     */
    public function testEncryptAll($radix, $key, $tweak, $plaintext, $ciphertext): void
    {
        $c = new FF3Cipher($key, $tweak, $radix);
        $s = $c->encrypt($plaintext);
        $this->assertEquals($ciphertext, $s, "Failed for test vector: " . json_encode([$radix, $key, $tweak, $plaintext, $ciphertext], JSON_THROW_ON_ERROR));
    }

    /**
     * @return void
     * @throws \Ivinco\Crypto\FF3Exception
     * @throws \JsonException
     * @dataProvider vectorsProvider
     */
    public function testDecryptAll($radix, $key, $tweak, $plaintext, $ciphertext): void
    {
        $c = new FF3Cipher($key, $tweak, $radix);
        $s = $c->decrypt($ciphertext);
        $this->assertEquals($plaintext, $s, "Failed for test vector: " . json_encode([$radix, $key, $tweak, $plaintext, $ciphertext], JSON_THROW_ON_ERROR));
    }

    /**
     * @return void
     * @throws \Ivinco\Crypto\FF3Exception
     * @throws \JsonException
     * @dataProvider vectorsACVPAESFF31Provider
     */
    public function testEncryptAcvp($radix, $alphabet, $key, $tweak, $plaintext, $ciphertext): void
    {
        $c = FF3Cipher::withCustomAlphabet($key, $tweak, $alphabet);
        $s = $c->encrypt($plaintext);
        $this->assertEquals($ciphertext, $s, "Failed for test vector: " . json_encode([$radix, $alphabet, $key, $tweak, $plaintext, $ciphertext], JSON_THROW_ON_ERROR));
    }

    /**
     * @return void
     * @throws \Ivinco\Crypto\FF3Exception
     * @throws \JsonException
     * @dataProvider vectorsACVPAESFF31Provider
     */
    public function testDecryptAcvp($radix, $alphabet, $key, $tweak, $plaintext, $ciphertext): void
    {
        $c = FF3Cipher::withCustomAlphabet($key, $tweak, $alphabet);
        $s = $c->decrypt($ciphertext);
        $this->assertEquals($plaintext, $s, "Failed for test vector: " . json_encode([$radix, $alphabet, $key, $tweak, $plaintext, $ciphertext], JSON_THROW_ON_ERROR));
    }

    public function testCustomAlphabet() {
        $alphabet = "⁰¹²³⁴⁵⁶⁷⁸⁹";
        $key = "EF4359D8D580AA4F7F036D6F04FC6A94";
        $tweak = "D8E7920AFA330A73";
        $plaintext = "⁸⁹⁰¹²¹²³⁴⁵⁶⁷⁸⁹⁰⁰⁰⁰";
        $ciphertext = "⁷⁵⁰⁹¹⁸⁸¹⁴⁰⁵⁸⁶⁵⁴⁶⁰⁷";

        $c = FF3Cipher::withCustomAlphabet($key, $tweak, $alphabet);
        $s = $c->encrypt($plaintext);
        $this->assertEquals($ciphertext, $s);

        $x = $c->decrypt($s);
        $this->assertEquals($plaintext, $x);
    }

    public function testGerman() {
        $german_alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZÄäÖöÜüẞß';
        $key = "EF4359D8D580AA4F7F036D6F04FC6A94";
        $tweak = "D8E7920AFA330A73";
        $plaintext = "liebeGrüße";
        $ciphertext = "5kÖQbairXo";

        $c = FF3Cipher::withCustomAlphabet($key, $tweak, $german_alphabet);
        $s = $c->encrypt($plaintext);
        $this->assertEquals($ciphertext, $s);

        $x = $c->decrypt($s);
        $this->assertEquals($plaintext, $x);
    }
}
