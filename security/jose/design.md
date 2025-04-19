# JSON Object Signing and Encryption (JOSE) Implementation

JOSE is a group of specifications supporting the creation of a JSON web token (JWT).  You can learn more [here](https://datatracker.ietf.org/wg/jose/about/)

## References

- [JSON Web Signature (JWS) Specification](https://datatracker.ietf.org/doc/rfc7515/)
- [JSON Web Encryption (JWE) Specification](https://datatracker.ietf.org/doc/rfc7516/)
- [JSON Web Key (JWK) Specification](https://datatracker.ietf.org/doc/rfc7517/)
- [JSON Web Algorithms (JWA) Specification](https://datatracker.ietf.org/doc/rfc7518/)
- [JOSE Usage Examples](https://datatracker.ietf.org/doc/rfc7520/)
- [OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [OAuth 2.0 Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)

## Psuedo Code

```rust

// Jwt Die
// Jws Template
// Jwe Template
// subject claims
// 

let token_mint = JoseMint::default()
    .issuer()
    .jwks_uri()
    .jwk()
    .encryption_keys()
    .compression()
    

let claims = JwtClaims::default();
token_mint.new_jws().payload(claims).sign();
token_mint.new_jwe().payload(claims).encrypt_sign();
let jwt = jws.payload(claims).sign();
    


```