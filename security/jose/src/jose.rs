/// [JOSE Header - Algorithm](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1)
/// Defined alg values are found here: [JSON Web Algorithms [JWA])(https://www.rfc-editor.org/rfc/rfc7518)
static JOSE_ALG: &str = "alg";
/// [JOSE Header - JWK Set URL (provides list of keys published the service that provided the JWS (signed token))](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.2)
/// This parameter is optional.
static JOSE_JKU: &str = "jku";
/// [JOSE Header - JSON Web Key](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.3)
/// The public key associated with the private key used to create the JWS.
/// This parameter is optional.
static JOSE_JWK: &str = "jwk";
/// [JOSE Header - Key Id](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.4)
/// This is the key id of the key used to sign the JWS.  If the signer of the JWS publishes
/// multiple keys in their JWK set, this is used to identify the specific key.
static JOSE_KID: &str = "kid";
/// [JOSE Header - URI to X509 Certificate or Certificate Chain](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.5)
/// This parameter is optional.
static JOSE_X5U: &str = "x5u";
/// [JOSE Header - The X509 Certificate or Certificate Chain](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.6)
/// This parameter is optional.
static JOSE_X5C: &str = "x5c";
/// [JOSE Header - The X509 SHA-1 Thumbprint](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.7)
/// This parameter is optional
static JOSE_X5T: &str = "x5t";
/// [JOSE Header - The X509 SHA-256 Thumbprint](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.8)
/// This parameter is optional.
static JOSE_X5T_S256: &str = "x5t#S256";
/// [JOSE Header - For JWS indicates the media type of the complete JWS](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.9)
/// This parameter is optional.
static JOSE_TYP: &str = "typ";
/// [JOSE Header - For JWS indicates the media type of the payload](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.8)
/// This parameter is optional.
static JOSE_CTY: &str = "cty";
/// [JOSE Header - Indicates that there are extensions that must 
/// be processed.](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.8)
/// This parameter is optional.
static JOSE_CRIT: &str = "crit";


pub struct Jose {

}

impl Jose {
    /// Creates a an new JSON Web Signature
    /// for now compact
    pub fn sign() -> String {
        panic!("Not implemented yet");
    }

    /// Creates a new JSON Web Encryption
    /// for now compact only
    pub fn encrypt() -> String {
        panic!("Not implemented yet");
    }
}
