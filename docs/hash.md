# lstrojny\scrypt\hash()

## Derive a new key from a secret

To derive a new key from a secret (e.g. a password) use `lstrojny\scrypt\hash()`. The function’s prototype looks like this:

```php
string lstrojny\scrypt\hash(
    string $secret,
    string $salt = null,
    array $options = [
        'cpu_cost' => 2 ^^ 14,
        'memory_cost' => 8,
        'parallelization_cost' => 1,
        'key_length' => 64,
    ]
) throws lstrojny\scrypt\exception\ScryptExceptionInterface
```

Pass the string to derive a key from as `$secret` and pass a good salt to increase the security of the derived key. Use [`openssl_random_pseudo_bytes()`](http://us3.php.net/openssl_random_pseudo_bytes) to generate a good hash.

### Work factors

Customize the work factors `cpu_cost` (sometimes called `N`), `memory_cost` (sometimes referred to as `r`) and `parallelization_cost` (sometimes called `p`)  for your needs. The defaults are picked to suffice the usual web application use case but you definitely need to adjust them according to the hardware at hand.

### Exceptions

If any of the parameters are invalid, an exception of type `lstrojny\scrypt\exception\InvalidArgumentException` is thrown. It extends `InvalidArgumentException` from PHP’s `ext/spl`.
If a runtime exception happens, an exception of type `lstrojny\scrypt\exception\RuntimeException` is thrown. It, similarly, extends `RuntimeException` (from PHP’s `ext/spl` as well).
Both exception classes implement a [marker interface](https://en.wikipedia.org/wiki/Marker_interface_pattern) of type `lstrojny\scrypt\exception\ScryptExceptionInterface`. A typical exception handling pattern will look like this:

```php
use lstrojny\scrypt\exception\ScryptExceptionInterface;
use lstrojny\scrypt;

try {
    scrypt\hash('secret', $salt);
} catch (ScryptExceptionInterface $e) {
    // Handle exception
}
```

### Return value

The return value of `lstrojny\scrypt\hash()` will depend on the work factors, the key length and the salt. All the parameters used to derive the key are encoded into the resulting hash to easy verifying the key. An example (spaces are only for legibility and not present in the original return value):

```
65536   $   8    $    1    $    64   $   YWFhh…YWFhYWE=   $   293567c1b393f13f2…1be91b
  ↑         ↑         ↑         ↑             ↑                            ↑ 
cpu       memory    parall.    key          salt                  actual key
cost      cost      cost       length       base64                (size depends
param     param     param      param        encoded               on key length)

```


