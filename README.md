Simple Asymmetric Crypt
=======================

Asymmetric key cryptography as simple as it gets.

This small class lets you create an asymmetric key pair, encrypt and decrypt
any data you want, making it ideal for securely transactioning your private
lolcats across the Interwebs.

## Creating a key pair

There are two ways to create a key pair, both have the same result, except
one returns the key pair as an array and the other stores them directly in
specified files.

First of all we need to instantiate the class:

```php
<?php

$sac = new SimpleAsymmetricCrypt;

?>
```

The construct method takes to optional parameters `$pri_key_ext` and
`$pub_key_ext` which specify the extension of the private and public key
files. They default to `'.key'` for private keys and `'.pub'` for public.

To create a key pair without saving the keys to a file, you need to call
`createKey()`, the method takes two arguments: `$passphrase` (required)
and `$bits` (optional, defaults to 1024).

The smalles key pair is 384 bits.

```php
<?php

$pair = $sac->createKey( 'some random passphrase' );

?>
```

This returns the following array:

```
array(2) {
    'private' => string(916) "-----BEGIN PRIVATE KEY-----  
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKzU62zQ5hIAfJ/L\nBkaMVk"...
    'public' => string(272) "-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCs1Ots0OYSAHyfywZGjFZKn/od\nR72E+6"...
}
```

To create and save a key pair call `createKeyFiles`. This method takes three
parameters, `$filename`, `$passphrase` and the optional `$bits`:

```php
<?php

$sac->createKeyFiles('key-fname', 'a passphrase here', 384);

?>
```

The code above will create a 384bit key pair and save the files as
`key-fname.key` for the private key and `key-fname.pub` for the public key.

Distribute the public key to anyone you may want to receive encrypted data
from.

**Important!** `$filename` is relative to the file executing the code, so make
sure that you resolve the path to a secure location.

## Encrypting data

To encrypt some sensible data you need to load a public key and call the
`encrypt` function.

_Remember that the encryptable data must be 88bits smaller than the key,
since that's the padding needed according to PKCS#1 Standard used by
OpenSSL, more on this below._

```php
<?php

$sac->setPublicKey('key_fname.pub'); // Set the pub key to use
$encrypted = $sac->encrypt("Some data to encrypt");

?>
```

`$encrypted` will now have a base64 encoded version of the encrypted
content.

### Base64 encoding

By default, `encrypt()` returns the encrypted data as a base64 encoded
string with chunk split. Base64 encoding and chink splitting can both be
disabled by calling `useBase64()`, which takes 2 parameters, `$use`
(required, boolean) and `$chunk_split` (optional, boolean, defaults to
FALSE).

## Data size and padding

> Basically when you encrypt something using an RSA key (whether public or
> private), the encrypted value must be smaller than the key (due to the maths
> used to do the actual encryption). So if you have a 1024-bit key, in theory
> you could encrypt any 1023-bit value (or a 1024-bit value smaller than the
> key) with that key.
> 
> However, the PKCS#1 standard, which OpenSSL uses, specifies a padding scheme
> (so you can encrypt smaller quantities without losing security), and that
> padding scheme takes a minimum of 11 bytes (it will be longer if the value
> you're encrypting is smaller). So the highest number of bits you can encrypt
> with a 1024-bit key is 936 bits because of this (unless you disable the
> padding by adding the OPENSSL_NO_PADDING flag, in which case you can go up to
> 1023-1024 bits). With a 2048-bit key it's 1960 bits instead.
> 
> But as chsnyder correctly wrote, the normal application of a public key
> encryption algorithm is to store a key or a hash of the data you want to
> respectively encrypt or sign. A hash is typically 128-256 bits (the PHP sha1()
> function returns a 160 bit hash). And an AES key is 128 to 256 bits. So either
> of those will comfortably fit inside a single RSA encryption.

_&mdash;[Thomas Horsten comment on php.net](http://php.net/openssl_public_encrypt#55901)</a>_

As Thomas Horsten commented on the php.net site, the PKCS#1 standard requires a
minimum of 11 bytes (88 bits) of padding, so if we translate that to character
length (utf-8) in a 1024 key, for example, you could store a maximum of 117
characters.

`( 1024 - 88 ) = 936 bits / 8 (a utf-8 char) = 117`

## License

Released under MIT License

Copyright (c) 2010 Luciano Longo

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
