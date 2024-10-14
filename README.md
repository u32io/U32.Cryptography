# U32.Cryptography

Cryptographic functions and types simplified and tailed for ease-of-use in applications.

## Types and Functions

- [Argon2](#argon2)
  - Argon2id
  - Argon2i
  - Argon2d

### Argon2

Create a hash from a `string`:
```csharp
var hash = Argon2Hash.FromArgon2D(Encoding.UTF8.GetBytes(password));
```

Create a hash from bytes (after they have been hashed):
```csharp
var hash = Argon2Hash.FromBytes(source.Bytes, source.Salt.Length);
```