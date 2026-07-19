# Various encryption helpers

Various PHP encryption helpers, uses [`paragonie/halite`](https://github.com/paragonie/halite) (which uses [Sodium](https://php.net/sodium)) for cryptography. Supports key rotation.

[![PHP Tests](https://github.com/spaze/encryption/actions/workflows/php.yml/badge.svg)](https://github.com/spaze/encryption/actions/workflows/php.yml)

## Installation
```bash
composer require spaze/encryption
```

## Usage
This library provides authenticated symmetric encryption using [Halite](https://github.com/paragonie/halite), which relies on [libsodium](https://pecl.php.net/package/libsodium) for all of its underlying cryptography operations.
Read the [Halite documentation](https://github.com/paragonie/halite/tree/master/doc) for more details, including the [cryptography primitives](https://github.com/paragonie/halite/blob/master/doc/Primitives.md) it uses.
At the moment, asymmetric encryption and signatures are not supported by this library.

The library is framework-agnostic, with minimal dependencies.

### Create the object using the constructor
```php
Spaze\Encryption\SymmetricKeyEncryption::__construct(array $keys, string $activeKeyId, string $keyPrefix)
```
#### `array $keys`
An array of encryption keys, a _key id_ (will be part of the encrypted string) as the array key, the prefixed _key_ (`prefix` + `_` + `[0-9A-F]{64}`) as the value.
Generate your own encryption keys with for example `bin2hex(random_bytes(32))`.
The library does not validate key format, it assumes you provide correct prefix + 64 hex characters.

#### `string $activeKeyId`
A `key id` of a key that should be used for encryption. Decryption will always use a key that's specified in the encryption output.

#### `string $keyPrefix`
A prefix that the encryption key uses for better identification, useful when you've found some leaked credentials for example.
Usually this is an abbreviation or an initialism of the intended usage, for example `adek`: *a*ddress *d*ata *e*ncryption *k*ey.

Example:
```php
$keys = [
    'key1' => 'adek_79e0[...]8a8d',
    'key2' => 'adek_d22c[...]cfa3',
];
$activeKeyId = 'key2';
$keyPrefix = 'adek';
$encryption = new Spaze\Encryption\SymmetricKeyEncryption($keys, $activeKeyId, $keyPrefix);
```

### Encrypt
```php
Spaze\Encryption\SymmetricKeyEncryption::encrypt(string $data): string
```
The output will be formatted as `$<keyId>$<base64 ciphertext>`, for example `$key2$MUI...`, where `<keyId>` (`key2`) is the active key id set in the constructor. Store the whole value, don't parse it.

This method does not use any context binding (Additional Authenticated Data). Use `encryptWithAd()` if you want to bind the ciphertext to a specific context.

Example:
```php
$encrypted = $encryption->encrypt($addressData);
```

### Encrypt with Additional Authenticated Data (AAD)
```php
Spaze\Encryption\SymmetricKeyEncryption::encryptWithAd(string $data, string $additionalData): string
```
Additional Authenticated Data (AAD) cryptographically binds a ciphertext to a context (like a row id, column name, or tenant id). The additional data (the context) is **not encrypted**, and thus it must not be a secret. This prevents attackers or buggy scripts from copying a valid ciphertext from one place and pasting it into another.

The `$additionalData` must be non-empty and exactly the same on both encrypt and decrypt, otherwise decryption will fail.

Example:
```php
$encrypted = $encryption->encryptWithAd($addressData, $tenantId);
```

### Decrypt
```php
Spaze\Encryption\SymmetricKeyEncryption::decrypt(string $data): string
```
Use it to decrypt data previously encrypted with `encrypt()`.

Example:
```php
$decrypted = $encryption->decrypt($encrypted);
```

### Decrypt with Additional Authenticated Data (AAD)
```php
Spaze\Encryption\SymmetricKeyEncryption::decryptWithAd(string $data, string $additionalData): string
```
Use it to decrypt data previously encrypted with `encryptWithAd()`.

Example:
```php
$decrypted = $encryption->decryptWithAd($encrypted, $tenantId);
```

### Key rotation
You can always add a new encryption key, set it as an active key and from that moment, the data will be encrypted with the new key.
Unless you remove the old key, it will be possible to decrypt data encrypted with it.
You can then take all the data encrypted with the old key and re-encrypt them just to change the key which was used to encrypt them.
Once done you can delete the old key.

You can use `needsReEncrypt($ciphertext): bool` to see if the data is encrypted with an inactive key and thus should be re-encrypted with the currently active one.

## Usage in Nette framework

Although it can be used anywhere, this library doesn't depend on anything from the Nette Framework.

### Define encryption keys

Add this (or similar) to your `config.local.neon` parameters section (DO NOT COMMIT THIS TO REPOSITORY):
```
parameters:
    encryption:
        keys:
            passwordHash:
                prod1: "phek_abadcafec15c..." # prefix _ [0-9A-F]{64}
            email:
                prod1: "eek_cafebabe25da..." # prefix _ [0-9A-F]{64}
        activeKeyIds:
            passwordHash: prod1
            email: prod1
        prefixes:
            passwordHash: phek # password hash encryption key
            email: eek # email encryption key
```
YOU HAVE TO GENERATE YOUR OWN KEYS. You can use for example
```php
bin2hex(random_bytes(32))
```
to generate a key, then add the prefix. You can have multiple keys in each group (here we see two groups: `password` and `email`), meaning you will be able to decrypt data encrypted with these keys. Data will always be encrypted with what's defined in `activeKeyIds` section.

The configuration is an example one, you don't need to use groups, or even the config key names (like `activeKeyIds`), the only place where these will be used is when you define the service, or services. 

### Services
Then define services for each key group (feel free to commit this):
```
services:
    emailEncryption: \Spaze\Encryption\SymmetricKeyEncryption(%encryption.keys.email%, %encryption.activeKeyIds.email%, %encryption.prefixes.email%)
    passwordHashEncryption: \Spaze\Encryption\SymmetricKeyEncryption(%encryption.keys.passwordHash%, %encryption.activeKeyIds.passwordHash%, %encryption.prefixes.passwordHash%)
```

Use the services in this class which needs to encrypt and decrypt email addresses for whatever reason:
```php
use Spaze\Encryption\SymmetricKeyEncryption;

class Something
{

    public function __construct(
        private SymmetricKeyEncryption $emailEncryption,
    ) {
        // ...
    }

    public function doSomething()
    {
        // ...
        $encryptedEmail = $this->emailEncryption->encrypt($email);
        // ...
    }


    public function doSomethingElse()
    {
        // ...
        $decryptedEmail = $this->emailEncryption->decrypt($email);
        // ...
    }

}
```

Pass the properly configured encryption service to the class:
```
services:
    something: Something(emailEncryption: @emailEncryption)
```

## Running tests

If you want to contribute (awesome, thanks!), you should add/run tests for your contributions.
First install dev dependencies by running `composer install`, then run tests with `composer test`, see `scripts` in `composer.json`. Tests are also run on GitHub with Actions on each push.

You can fix coding style issues automatically by running `composer cs-fix`.
