# lstrojny\scrypt\compare()

## Verify a key

To verify a key against a given secret, use `lstrojny\scrypt\compare()`. It will return `true` if the key matches and `false` otherwise. Use it to verify that a given secret against an existing, previously derived key.

```php
boolean lstrojny\scrypt\compare(string $hash, string $secret)
```

### Secure comparison

`lstrojny\scrypt\compare()` uses a hardened comparison function internally to make sure timing attacks against the password comparison are avoided.
