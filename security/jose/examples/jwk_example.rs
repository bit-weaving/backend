// Modified by Claude AI Assistant - Updated to use new builder pattern with immutable Jwk
use jose::jwk::{Jwk, JwkBuilder, JwkSet, KeyOperation, KeyType, PublicKeyUse};
use jose::jws::JwsAlgorithm;
use serde_json;

fn main() {
    println!("=== JSON Web Key (JWK) Examples ===\n");

    // Example 1: Create an RSA JWK for signing
    let rsa_jwk = Jwk::builder(KeyType::Rsa)
        .with_key_id("rsa-key-1".to_string())
        .with_algorithm(JwsAlgorithm::RS256)
        .with_public_key_use(PublicKeyUse::Signature)
        .with_key_operations(vec![KeyOperation::Sign, KeyOperation::Verify])
        .with_key_param("n", "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")
        .with_key_param("e", "AQAB")
        .build()
        .unwrap();

    println!("1. RSA JWK for signing:");
    println!("{}\n", serde_json::to_string_pretty(&rsa_jwk).unwrap());

    // Example 2: Create an Elliptic Curve JWK for encryption
    let ec_jwk = Jwk::builder(KeyType::EllipticCurve)
        .with_key_id("ec-key-1".to_string())
        .with_algorithm(JwsAlgorithm::ES256)
        .with_public_key_use(PublicKeyUse::Encryption)
        .with_key_operations(vec![KeyOperation::Encrypt, KeyOperation::Decrypt])
        .with_key_param("crv", "P-256")
        .with_key_param("x", "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4")
        .with_key_param("y", "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM")
        .build()
        .unwrap();

    println!("2. Elliptic Curve JWK for encryption:");
    println!("{}\n", serde_json::to_string_pretty(&ec_jwk).unwrap());

    // Example 3: Create a symmetric key JWK
    let symmetric_jwk = Jwk::builder(KeyType::OctetSequence)
        .with_key_id("hmac-key-1".to_string())
        .with_key_operations(vec![KeyOperation::Sign, KeyOperation::Verify])
        .with_key_param("k", "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")
        .build()
        .unwrap();

    println!("3. Symmetric key JWK:");
    println!(
        "{}\n",
        serde_json::to_string_pretty(&symmetric_jwk).unwrap()
    );

    // Example 4: Create a JWK Set
    let jwk_set = JwkSet::new()
        .add_key(rsa_jwk)
        .add_key(ec_jwk)
        .add_key(symmetric_jwk);

    println!("4. JWK Set with multiple keys:");
    println!("{}\n", serde_json::to_string_pretty(&jwk_set).unwrap());

    // Example 5: Demonstrate JWK Set operations
    println!("5. JWK Set operations:");

    if let Some(key) = jwk_set.find_key_by_id("rsa-key-1") {
        println!("Found RSA key: {:?}", key.kty());
    }

    let signing_keys = jwk_set.find_keys_by_use(&PublicKeyUse::Signature);
    println!("Found {} signing keys", signing_keys.len());

    let rs256_keys = jwk_set.find_keys_by_algorithm(&JwsAlgorithm::RS256);
    println!("Found {} RS256 keys", rs256_keys.len());

    // Example 6: Demonstrate key usage validation
    println!("\n6. Key usage consistency validation:");

    let consistent_key = Jwk::builder(KeyType::Rsa)
        .with_public_key_use(PublicKeyUse::Signature)
        .with_key_operations(vec![KeyOperation::Sign, KeyOperation::Verify])
        .build();

    println!(
        "Consistent key (sig use with sign/verify ops): {}",
        consistent_key.is_ok()
    );

    let inconsistent_key = Jwk::builder(KeyType::Rsa)
        .with_public_key_use(PublicKeyUse::Signature)
        .with_key_operations(vec![KeyOperation::Encrypt])
        .build();

    println!(
        "Inconsistent key (sig use with encrypt op): {}",
        inconsistent_key.is_err()
    );
}
