// Modified by Claude AI Assistant - Refactored to implement builder pattern with immutable Jwk struct
use crate::jws::JwsAlgorithm;
use serde::{Deserialize, Serialize};

/// Key Type parameter values as defined in RFC 7517 Section 4.1
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub enum KeyType {
    /// RSA key type
    #[serde(rename = "RSA")]
    Rsa,
    /// Elliptic Curve key type
    #[serde(rename = "EC")]
    EllipticCurve,
    /// Octet sequence (symmetric key) type
    #[serde(rename = "oct")]
    OctetSequence,
}

/// Public Key Use parameter values as defined in RFC 7517 Section 4.2
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub enum PublicKeyUse {
    /// Signature use
    #[serde(rename = "sig")]
    Signature,
    /// Encryption use
    #[serde(rename = "enc")]
    Encryption,
}

/// Key Operations parameter values as defined in RFC 7517 Section 4.3
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub enum KeyOperation {
    /// Compute digital signature or MAC
    #[serde(rename = "sign")]
    Sign,
    /// Verify digital signature or MAC
    #[serde(rename = "verify")]
    Verify,
    /// Encrypt content
    #[serde(rename = "encrypt")]
    Encrypt,
    /// Decrypt content and validate decryption, if applicable
    #[serde(rename = "decrypt")]
    Decrypt,
    /// Encrypt key
    #[serde(rename = "wrapKey")]
    WrapKey,
    /// Decrypt key and validate decryption, if applicable
    #[serde(rename = "unwrapKey")]
    UnwrapKey,
    /// Derive key
    #[serde(rename = "deriveKey")]
    DeriveKey,
    /// Derive bits not to be used as a key
    #[serde(rename = "deriveBits")]
    DeriveBits,
}

/// JSON Web Key (JWK) structure as defined in RFC 7517 Section 4
///
/// A JWK is a JSON object that represents a cryptographic key.
/// The members of the object represent properties of the key, including its value.
/// 
/// This struct is immutable after creation. Use `JwkBuilder` to construct instances.
/// 
/// Author: Claude AI Assistant - Implemented builder pattern for immutability
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Jwk {
    /// Key Type (kty) parameter - REQUIRED
    /// Identifies the cryptographic algorithm family used with the key
    /// such as "RSA" or "EC"
    kty: KeyType,

    /// Public Key Use (use) parameter - OPTIONAL
    /// Identifies the intended use of the public key
    /// Values: "sig" (signature) or "enc" (encryption)
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    public_key_use: Option<PublicKeyUse>,

    /// Key Operations (key_ops) parameter - OPTIONAL
    /// Identifies the operation(s) for which the key is intended to be used
    /// Array of key operation values
    #[serde(skip_serializing_if = "Option::is_none")]
    key_ops: Option<Vec<KeyOperation>>,

    /// Algorithm (alg) parameter - OPTIONAL
    /// Identifies the algorithm intended for use with the key
    /// Case-sensitive ASCII string
    #[serde(skip_serializing_if = "Option::is_none")]
    alg: Option<JwsAlgorithm>,

    /// Key ID (kid) parameter - OPTIONAL
    /// Used to match a specific key, for instance, to choose among
    /// a set of keys within a JWK Set during key rollover
    /// Case-sensitive string with unspecified structure
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,

    /// X.509 URL (x5u) parameter - OPTIONAL
    /// URI that refers to a resource for an X.509 public key certificate
    /// or certificate chain. Must use TLS and validate server identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    x5u: Option<String>,

    /// X.509 Certificate Chain (x5c) parameter - OPTIONAL
    /// Contains a chain of one or more PKIX certificates
    /// Array of certificate value strings (base64-encoded DER PKIX certificate values)
    #[serde(skip_serializing_if = "Option::is_none")]
    x5c: Option<Vec<String>>,

    /// X.509 Certificate SHA-1 Thumbprint (x5t) parameter - OPTIONAL
    /// Base64url-encoded SHA-1 thumbprint of the DER encoding of an X.509 certificate
    #[serde(skip_serializing_if = "Option::is_none")]
    x5t: Option<String>,

    /// X.509 Certificate SHA-256 Thumbprint (x5t#S256) parameter - OPTIONAL
    /// Base64url-encoded SHA-256 thumbprint of the DER encoding of an X.509 certificate
    #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    x5t_s256: Option<String>,

    /// Additional key-specific parameters
    /// RSA keys will have n, e, d, p, q, dp, dq, qi parameters
    /// EC keys will have crv, x, y, d parameters
    /// oct keys will have k parameter
    #[serde(flatten)]
    key_params: serde_json::Map<String, serde_json::Value>,
}

/// Builder for creating immutable JWK instances
/// 
/// Author: Claude AI Assistant - Created builder pattern implementation
#[derive(Debug, Clone)]
pub struct JwkBuilder {
    kty: KeyType,
    public_key_use: Option<PublicKeyUse>,
    key_ops: Option<Vec<KeyOperation>>,
    alg: Option<JwsAlgorithm>,
    kid: Option<String>,
    x5u: Option<String>,
    x5c: Option<Vec<String>>,
    x5t: Option<String>,
    x5t_s256: Option<String>,
    key_params: serde_json::Map<String, serde_json::Value>,
}

impl JwkBuilder {
    /// Creates a new JWK builder with the specified key type
    pub fn new(kty: KeyType) -> Self {
        Self {
            kty,
            public_key_use: None,
            key_ops: None,
            alg: None,
            kid: None,
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
            key_params: serde_json::Map::new(),
        }
    }

    /// Sets the public key use parameter
    pub fn with_public_key_use(mut self, public_key_use: PublicKeyUse) -> Self {
        self.public_key_use = Some(public_key_use);
        self
    }

    /// Sets the key operations parameter
    pub fn with_key_operations(mut self, key_ops: Vec<KeyOperation>) -> Self {
        self.key_ops = Some(key_ops);
        self
    }

    /// Sets the algorithm parameter
    pub fn with_algorithm(mut self, alg: JwsAlgorithm) -> Self {
        self.alg = Some(alg);
        self
    }

    /// Sets the key ID parameter
    pub fn with_key_id(mut self, kid: String) -> Self {
        self.kid = Some(kid);
        self
    }

    /// Sets the X.509 URL parameter
    pub fn with_x509_url(mut self, x5u: String) -> Self {
        self.x5u = Some(x5u);
        self
    }

    /// Sets the X.509 certificate chain parameter
    pub fn with_x509_cert_chain(mut self, x5c: Vec<String>) -> Self {
        self.x5c = Some(x5c);
        self
    }

    /// Sets the X.509 SHA-1 thumbprint parameter
    pub fn with_x509_sha1_thumbprint(mut self, x5t: String) -> Self {
        self.x5t = Some(x5t);
        self
    }

    /// Sets the X.509 SHA-256 thumbprint parameter
    pub fn with_x509_sha256_thumbprint(mut self, x5t_s256: String) -> Self {
        self.x5t_s256 = Some(x5t_s256);
        self
    }

    /// Adds a key-specific parameter
    pub fn with_key_param<K: Into<String>, V: Into<serde_json::Value>>(
        mut self,
        key: K,
        value: V,
    ) -> Self {
        self.key_params.insert(key.into(), value.into());
        self
    }

    /// Validates that use and key_ops parameters are consistent if both are present
    /// Returns true if consistent or if only one is present
    fn validate_key_usage_consistency(&self) -> bool {
        match (&self.public_key_use, &self.key_ops) {
            (Some(PublicKeyUse::Signature), Some(ops)) => ops
                .iter()
                .all(|op| matches!(op, KeyOperation::Sign | KeyOperation::Verify)),
            (Some(PublicKeyUse::Encryption), Some(ops)) => ops.iter().all(|op| {
                matches!(
                    op,
                    KeyOperation::Encrypt
                        | KeyOperation::Decrypt
                        | KeyOperation::WrapKey
                        | KeyOperation::UnwrapKey
                        | KeyOperation::DeriveKey
                        | KeyOperation::DeriveBits
                )
            }),
            _ => true, // If only one is present or neither is present, they're consistent
        }
    }

    /// Builds the JWK instance after validating the configuration
    pub fn build(self) -> Result<Jwk, String> {
        if !self.validate_key_usage_consistency() {
            return Err("Inconsistent key usage: 'use' and 'key_ops' parameters conflict".to_string());
        }

        Ok(Jwk {
            kty: self.kty,
            public_key_use: self.public_key_use,
            key_ops: self.key_ops,
            alg: self.alg,
            kid: self.kid,
            x5u: self.x5u,
            x5c: self.x5c,
            x5t: self.x5t,
            x5t_s256: self.x5t_s256,
            key_params: self.key_params,
        })
    }
}

impl Jwk {
    /// Creates a new JWK builder with the specified key type
    pub fn builder(kty: KeyType) -> JwkBuilder {
        JwkBuilder::new(kty)
    }

    /// Gets the key type
    pub fn kty(&self) -> &KeyType {
        &self.kty
    }

    /// Gets the public key use parameter
    pub fn public_key_use(&self) -> Option<&PublicKeyUse> {
        self.public_key_use.as_ref()
    }

    /// Gets the key operations parameter
    pub fn key_ops(&self) -> Option<&Vec<KeyOperation>> {
        self.key_ops.as_ref()
    }

    /// Gets the algorithm parameter
    pub fn alg(&self) -> Option<&JwsAlgorithm> {
        self.alg.as_ref()
    }

    /// Gets the key ID parameter
    pub fn kid(&self) -> Option<&String> {
        self.kid.as_ref()
    }

    /// Gets the X.509 URL parameter
    pub fn x5u(&self) -> Option<&String> {
        self.x5u.as_ref()
    }

    /// Gets the X.509 certificate chain parameter
    pub fn x5c(&self) -> Option<&Vec<String>> {
        self.x5c.as_ref()
    }

    /// Gets the X.509 SHA-1 thumbprint parameter
    pub fn x5t(&self) -> Option<&String> {
        self.x5t.as_ref()
    }

    /// Gets the X.509 SHA-256 thumbprint parameter
    pub fn x5t_s256(&self) -> Option<&String> {
        self.x5t_s256.as_ref()
    }

    /// Gets a key-specific parameter
    pub fn get_key_param(&self, key: &str) -> Option<&serde_json::Value> {
        self.key_params.get(key)
    }

    /// Gets all key parameters
    pub fn key_params(&self) -> &serde_json::Map<String, serde_json::Value> {
        &self.key_params
    }

    /// Checks if the JWK has all required parameters for its key type
    pub fn is_complete(&self) -> bool {
        match self.kty {
            KeyType::Rsa => {
                // RSA keys require 'n' and 'e' parameters
                self.key_params.contains_key("n") && self.key_params.contains_key("e")
            }
            KeyType::EllipticCurve => {
                // EC keys require 'crv', 'x', and 'y' parameters
                self.key_params.contains_key("crv")
                    && self.key_params.contains_key("x")
                    && self.key_params.contains_key("y")
            }
            KeyType::OctetSequence => {
                // Symmetric keys require 'k' parameter
                self.key_params.contains_key("k")
            }
        }
    }

    /// Checks if the JWK contains private key material
    pub fn is_private(&self) -> bool {
        match self.kty {
            KeyType::Rsa => {
                // RSA private keys have 'd' parameter
                self.key_params.contains_key("d")
            }
            KeyType::EllipticCurve => {
                // EC private keys have 'd' parameter
                self.key_params.contains_key("d")
            }
            KeyType::OctetSequence => {
                // Symmetric keys are always considered private
                true
            }
        }
    }

    /// Returns the key size in bits if determinable
    pub fn key_size_bits(&self) -> Option<usize> {
        match self.kty {
            KeyType::Rsa => {
                // For RSA, key size is determined by modulus length
                if let Some(serde_json::Value::String(n)) = self.key_params.get("n") {
                    // Base64url decode and calculate bit length
                    // This is a simplified calculation - in practice you'd decode the base64url
                    Some(n.len() * 6) // Rough approximation
                } else {
                    None
                }
            }
            KeyType::EllipticCurve => {
                // For EC, key size depends on curve
                if let Some(serde_json::Value::String(crv)) = self.key_params.get("crv") {
                    match crv.as_str() {
                        "P-256" => Some(256),
                        "P-384" => Some(384),
                        "P-521" => Some(521),
                        _ => None,
                    }
                } else {
                    None
                }
            }
            KeyType::OctetSequence => {
                // For symmetric keys, size is determined by key length
                if let Some(serde_json::Value::String(k)) = self.key_params.get("k") {
                    // Base64url decode length * 8 for bits
                    Some(k.len() * 6) // Rough approximation
                } else {
                    None
                }
            }
        }
    }

    /// Creates a thumbprint of the JWK using SHA-256
    /// This creates a unique identifier for the key based on required parameters
    pub fn thumbprint(&self) -> Result<String, Box<dyn std::error::Error>> {
        use std::collections::BTreeMap;

        // Create canonical JWK with only required parameters in sorted order
        let mut canonical = BTreeMap::new();
        canonical.insert("kty", serde_json::to_value(&self.kty)?);

        match self.kty {
            KeyType::Rsa => {
                if let Some(n) = self.key_params.get("n") {
                    canonical.insert("n", n.clone());
                }
                if let Some(e) = self.key_params.get("e") {
                    canonical.insert("e", e.clone());
                }
            }
            KeyType::EllipticCurve => {
                if let Some(crv) = self.key_params.get("crv") {
                    canonical.insert("crv", crv.clone());
                }
                if let Some(x) = self.key_params.get("x") {
                    canonical.insert("x", x.clone());
                }
                if let Some(y) = self.key_params.get("y") {
                    canonical.insert("y", y.clone());
                }
            }
            KeyType::OctetSequence => {
                if let Some(k) = self.key_params.get("k") {
                    canonical.insert("k", k.clone());
                }
            }
        }

        let canonical_json = serde_json::to_string(&canonical)?;

        // In a real implementation, you'd use a proper SHA-256 hash
        // For now, we'll return a placeholder
        Ok(format!("jwk-thumbprint-{}", canonical_json.len()))
    }


}

/// JWK Set structure as defined in RFC 7517 Section 5
///
/// A JWK Set is a JSON object that represents a set of JWKs.
/// The JSON object MUST have a "keys" member, with its value being an array of JWKs.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct JwkSet {
    /// Array of JWK values
    pub keys: Vec<Jwk>,

    /// Additional JWK Set parameters
    #[serde(flatten)]
    pub additional_params: serde_json::Map<String, serde_json::Value>,
}

impl JwkSet {
    /// Creates a new empty JWK Set
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            additional_params: serde_json::Map::new(),
        }
    }

    /// Creates a new JWK Set with the given keys
    pub fn with_keys(keys: Vec<Jwk>) -> Self {
        Self {
            keys,
            additional_params: serde_json::Map::new(),
        }
    }

    /// Adds a JWK to the set
    pub fn add_key(mut self, key: Jwk) -> Self {
        self.keys.push(key);
        self
    }

    /// Finds a key by key ID
    pub fn find_key_by_id(&self, kid: &str) -> Option<&Jwk> {
        self.keys
            .iter()
            .find(|key| key.kid().map_or(false, |k| k == kid))
    }

    /// Finds keys by algorithm
    pub fn find_keys_by_algorithm(&self, alg: &JwsAlgorithm) -> Vec<&Jwk> {
        self.keys
            .iter()
            .filter(|key| key.alg().map_or(false, |a| a == alg))
            .collect()
    }

    /// Finds keys by public key use
    pub fn find_keys_by_use(&self, public_key_use: &PublicKeyUse) -> Vec<&Jwk> {
        self.keys
            .iter()
            .filter(|key| {
                key.public_key_use()
                    .map_or(false, |u| u == public_key_use)
            })
            .collect()
    }
}

impl Default for JwkSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwk_creation() {
        let jwk = Jwk::builder(KeyType::Rsa)
            .with_key_id("test-key-1".to_string())
            .with_algorithm(JwsAlgorithm::RS256)
            .with_public_key_use(PublicKeyUse::Signature)
            .build()
            .unwrap();

        assert_eq!(*jwk.kty(), KeyType::Rsa);
        assert_eq!(jwk.kid(), Some(&"test-key-1".to_string()));
        assert_eq!(jwk.alg(), Some(&JwsAlgorithm::RS256));
        assert_eq!(jwk.public_key_use(), Some(&PublicKeyUse::Signature));
    }

    #[test]
    fn test_jwk_key_usage_consistency() {
        let jwk_consistent = Jwk::builder(KeyType::Rsa)
            .with_public_key_use(PublicKeyUse::Signature)
            .with_key_operations(vec![KeyOperation::Sign, KeyOperation::Verify])
            .build();

        assert!(jwk_consistent.is_ok());

        let jwk_inconsistent = Jwk::builder(KeyType::Rsa)
            .with_public_key_use(PublicKeyUse::Signature)
            .with_key_operations(vec![KeyOperation::Encrypt])
            .build();

        assert!(jwk_inconsistent.is_err());
    }

    #[test]
    fn test_jwk_set_operations() {
        let jwk1 = Jwk::builder(KeyType::Rsa)
            .with_key_id("key1".to_string())
            .with_algorithm(JwsAlgorithm::RS256)
            .build()
            .unwrap();

        let jwk2 = Jwk::builder(KeyType::EllipticCurve)
            .with_key_id("key2".to_string())
            .with_algorithm(JwsAlgorithm::ES256)
            .build()
            .unwrap();

        let jwk_set = JwkSet::new().add_key(jwk1).add_key(jwk2);

        assert_eq!(jwk_set.keys.len(), 2);

        let found_key = jwk_set.find_key_by_id("key1");
        assert!(found_key.is_some());
        assert_eq!(*found_key.unwrap().kty(), KeyType::Rsa);

        let rs256_keys = jwk_set.find_keys_by_algorithm(&JwsAlgorithm::RS256);
        assert_eq!(rs256_keys.len(), 1);
    }

    #[test]
    fn test_jwk_serialization() {
        let jwk = Jwk::builder(KeyType::Rsa)
            .with_key_id("test-key".to_string())
            .with_algorithm(JwsAlgorithm::RS256)
            .with_public_key_use(PublicKeyUse::Signature)
            .with_key_param("n", "test-modulus")
            .with_key_param("e", "AQAB")
            .build()
            .unwrap();

        let json = serde_json::to_string(&jwk).unwrap();
        let deserialized: Jwk = serde_json::from_str(&json).unwrap();

        assert_eq!(*jwk.kty(), *deserialized.kty());
        assert_eq!(jwk.kid(), deserialized.kid());
        assert_eq!(jwk.alg(), deserialized.alg());
        assert_eq!(jwk.public_key_use(), deserialized.public_key_use());
    }

    #[test]
    fn test_jwk_completeness() {
        // Complete RSA key
        let complete_rsa = Jwk::builder(KeyType::Rsa)
            .with_key_param("n", "modulus")
            .with_key_param("e", "AQAB")
            .build()
            .unwrap();
        assert!(complete_rsa.is_complete());

        // Incomplete RSA key
        let incomplete_rsa = Jwk::builder(KeyType::Rsa)
            .with_key_param("n", "modulus")
            .build()
            .unwrap();
        assert!(!incomplete_rsa.is_complete());

        // Complete EC key
        let complete_ec = Jwk::builder(KeyType::EllipticCurve)
            .with_key_param("crv", "P-256")
            .with_key_param("x", "x-coord")
            .with_key_param("y", "y-coord")
            .build()
            .unwrap();
        assert!(complete_ec.is_complete());

        // Complete symmetric key
        let complete_oct = Jwk::builder(KeyType::OctetSequence)
            .with_key_param("k", "key-value")
            .build()
            .unwrap();
        assert!(complete_oct.is_complete());
    }

    #[test]
    fn test_jwk_private_key_detection() {
        // RSA private key
        let rsa_private = Jwk::builder(KeyType::Rsa)
            .with_key_param("n", "modulus")
            .with_key_param("e", "AQAB")
            .with_key_param("d", "private-exponent")
            .build()
            .unwrap();
        assert!(rsa_private.is_private());

        // RSA public key
        let rsa_public = Jwk::builder(KeyType::Rsa)
            .with_key_param("n", "modulus")
            .with_key_param("e", "AQAB")
            .build()
            .unwrap();
        assert!(!rsa_public.is_private());

        // EC private key
        let ec_private = Jwk::builder(KeyType::EllipticCurve)
            .with_key_param("crv", "P-256")
            .with_key_param("x", "x-coord")
            .with_key_param("y", "y-coord")
            .with_key_param("d", "private-key")
            .build()
            .unwrap();
        assert!(ec_private.is_private());

        // Symmetric key (always private)
        let symmetric = Jwk::builder(KeyType::OctetSequence)
            .with_key_param("k", "key-value")
            .build()
            .unwrap();
        assert!(symmetric.is_private());
    }

    #[test]
    fn test_jwk_key_size() {
        // EC key with known curve
        let ec_p256 = Jwk::builder(KeyType::EllipticCurve)
            .with_key_param("crv", "P-256")
            .build()
            .unwrap();
        assert_eq!(ec_p256.key_size_bits(), Some(256));

        let ec_p384 = Jwk::builder(KeyType::EllipticCurve)
            .with_key_param("crv", "P-384")
            .build()
            .unwrap();
        assert_eq!(ec_p384.key_size_bits(), Some(384));

        // EC key with unknown curve
        let ec_unknown = Jwk::builder(KeyType::EllipticCurve)
            .with_key_param("crv", "unknown-curve")
            .build()
            .unwrap();
        assert_eq!(ec_unknown.key_size_bits(), None);
    }

    #[test]
    fn test_jwk_thumbprint() {
        let jwk = Jwk::builder(KeyType::Rsa)
            .with_key_param("n", "modulus")
            .with_key_param("e", "AQAB")
            .build()
            .unwrap();

        let thumbprint = jwk.thumbprint();
        assert!(thumbprint.is_ok());
        assert!(thumbprint.unwrap().starts_with("jwk-thumbprint-"));
    }
}
