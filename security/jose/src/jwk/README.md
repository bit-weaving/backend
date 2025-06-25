# JSON Web Key (JWK) Implementation

This module provides a complete implementation of JSON Web Key (JWK) as defined in [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517).

## Overview

A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key. This implementation includes all standard JWK parameters as specified in RFC 7517 Section 4.

## Features

- ✅ Complete RFC 7517 compliance
- ✅ All standard JWK parameters
- ✅ JWK Set support
- ✅ Key type validation
- ✅ Usage consistency validation
- ✅ Serde serialization/deserialization
- ✅ Builder pattern for easy construction

## Supported Key Types

| Key Type | Description | RFC Reference |
|----------|-------------|---------------|
| `RSA` | RSA keys | RFC 7518 Section 6.3 |
| `EC` | Elliptic Curve keys | RFC 7518 Section 6.2 |
| `oct` | Octet sequence (symmetric keys) | RFC 7518 Section 6.4 |

## JWK Parameters

### Required Parameters

- **kty** (Key Type): Identifies the cryptographic algorithm family

### Optional Parameters

- **use** (Public Key Use): Intended use of the public key
  - `sig` - Signature
  - `enc` - Encryption
- **key_ops** (Key Operations): Array of intended operations
  - `sign`, `verify`, `encrypt`, `decrypt`, `wrapKey`, `unwrapKey`, `deriveKey`, `deriveBits`
- **alg** (Algorithm): Algorithm intended for use with the key
- **kid** (Key ID): Key identifier for matching
- **x5u** (X.509 URL): URI referring to X.509 certificate/chain
- **x5c** (X.509 Certificate Chain): Array of X.509 certificates
- **x5t** (X.509 SHA-1 Thumbprint): SHA-1 thumbprint of X.509 certificate
- **x5t#S256** (X.509 SHA-256 Thumbprint): SHA-256 thumbprint of X.509 certificate

## Usage Examples

### Creating a JWK

```rust
use jose::jwk::{Jwk, KeyType, PublicKeyUse, KeyOperation};
use jose::jws::JwsAlgorithm;

// Create an RSA JWK for signing
let jwk = Jwk::new(KeyType::Rsa)
    .with_key_id("my-key-1".to_string())
    .with_algorithm(JwsAlgorithm::RS256)
    .with_public_key_use(PublicKeyUse::Signature)
    .with_key_operations(vec![KeyOperation::Sign, KeyOperation::Verify])
    .with_key_param("n", "modulus_value")
    .with_key_param("e", "AQAB");
```

### Creating a JWK Set

```rust
use jose::jwk::{JwkSet, Jwk, KeyType};

let jwk1 = Jwk::new(KeyType::Rsa).with_key_id("key1".to_string());
let jwk2 = Jwk::new(KeyType::EllipticCurve).with_key_id("key2".to_string());

let jwk_set = JwkSet::new()
    .add_key(jwk1)
    .add_key(jwk2);
```

### Finding Keys in a JWK Set

```rust
// Find by key ID
if let Some(key) = jwk_set.find_key_by_id("key1") {
    println!("Found key: {:?}", key.kty);
}

// Find by algorithm
let rs256_keys = jwk_set.find_keys_by_algorithm(&JwsAlgorithm::RS256);

// Find by usage
let signing_keys = jwk_set.find_keys_by_use(&PublicKeyUse::Signature);
```

### Serialization

```rust
// Serialize to JSON
let json = serde_json::to_string(&jwk)?;

// Deserialize from JSON
let jwk: Jwk = serde_json::from_str(&json)?;
```

## Key-Specific Parameters

Key-specific parameters are stored in the `key_params` field as a flexible JSON map:

### RSA Keys
- **n**: Modulus
- **e**: Exponent
- **d**: Private exponent (for private keys)
- **p**, **q**: Prime factors (for private keys)
- **dp**, **dq**, **qi**: CRT parameters (for private keys)

### Elliptic Curve Keys
- **crv**: Curve name (e.g., "P-256", "P-384", "P-521")
- **x**, **y**: Coordinate values
- **d**: Private key value (for private keys)

### Symmetric Keys
- **k**: Key value (base64url-encoded)

## Validation

The implementation includes validation for:

- **Usage Consistency**: Ensures `use` and `key_ops` parameters are consistent when both are present
- **Key Type Validation**: Validates that required key-specific parameters are present

```rust
// Validate usage consistency
let is_consistent = jwk.validate_key_usage_consistency();
```

## Security Considerations

Following RFC 7517 security guidelines:

1. **Key Provenance**: Validate the source and authenticity of keys
2. **Private Key Protection**: Use JWE encryption for private keys in transit/storage
3. **X.509 Validation**: When using X.509 parameters, validate certificates and chains
4. **TLS Requirements**: X.509 URL (`x5u`) must use TLS with proper server validation

## Example JWK Structure

```json
{
  "kty": "RSA",
  "use": "sig",
  "kid": "my-key-1",
  "alg": "RS256",
  "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQ...",
  "e": "AQAB"
}
```

## Example JWK Set Structure

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "rsa-key-1",
      "use": "sig",
      "alg": "RS256",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQ...",
      "e": "AQAB"
    },
    {
      "kty": "EC",
      "kid": "ec-key-1", 
      "use": "enc",
      "alg": "ES256",
      "crv": "P-256",
      "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
      "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
    }
  ]
}
```

## Error Handling

The implementation uses Rust's type system and `Option` types for optional parameters. Serialization errors are handled through the `serde` framework.

## Testing

Run the test suite:

```bash
cargo test jwk
```

## References

- [RFC 7517 - JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)
- [RFC 7518 - JSON Web Algorithms (JWA)](https://datatracker.ietf.org/doc/html/rfc7518)
- [IANA JSON Web Key Parameters Registry](https://www.iana.org/assignments/jose/jose.xhtml#web-key-parameters)