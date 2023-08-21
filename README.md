# FF3Cipher PHP Library

## Overview

FF3Cipher is a PHP implementation of the FF3 (Format-Preserving Encryption) algorithm.
This project was initiated because there was no existing FF3 implementation available
for PHP. With the growth of data protection needs and the wide adoption of PHP in web
applications, this project aims to bridge the gap, allowing developers to utilize FF3
encryption easily within their PHP applications.

## Installation

The recommended way to install FF3Cipher is through Composer:

```shell
composer require ivinco/crypto-ff3
```

Ensure your project's composer.json and the associated lock file are updated.

## Usage

### Basic Encryption & Decryption

```php
use Ivinco\Crypto\FF3Cipher;

$key = "EF4359D8D580AA4F7F036D6F04FC6A94"; // Your encryption key
$tweak = "D8E7920AFA330A73"; // Your tweak

$cipher = new FF3Cipher($key, $tweak);

$plaintext = "1234567890";
$ciphertext = $cipher->encrypt($plaintext);
echo "Ciphertext: " . $ciphertext . PHP_EOL;

$decrypted = $cipher->decrypt($ciphertext);
echo "Decrypted: " . $decrypted . PHP_EOL;
```

### Using Custom Alphabets

In some scenarios, you might want to work with non-standard characters.
This library supports encryption and decryption using custom alphabets:

```php
$alphabet = "abcdefghijklmnopqrstuvwxyz"; // Custom alphabet
$cipher = FF3Cipher::withCustomAlphabet($key, $tweak, $alphabet);

$plaintext = "wfmwlrorcd";
$ciphertext = $cipher->encrypt($plaintext);
echo "Ciphertext: " . $ciphertext . PHP_EOL; // ywowehycyd

$decrypted = $cipher->decrypt($ciphertext); // wfmwlrorcd
echo "Decrypted: " . $decrypted . PHP_EOL;
```

## Tests

The library is accompanied by unit tests.

Install the required packages via Composer:

```shell
composer install
```

Execute PHPUnit:

```shell
./vendor/bin/phpunit
```

## Links

For FF3 implementations in other languages, you can refer to:

* [Python Version](https://github.com/mysto/python-fpe)
* [Node.js Version](https://github.com/mysto/node-fpe)
* [Java Version](https://github.com/mysto/java-fpe)
* [C Version](https://github.com/mysto/clang-fpe)
