use serde::Deserialize;
use serde::Serialize;

use crate::jws::JwsAlgorithm;

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "alg")]
struct Algorithm(JwsAlgorithm);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "jwu")]
struct JsonWebKeySetUrl(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "jwk")]
struct JsonWebKey(String);

#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
#[serde(rename = "kid")]
struct KeyIdentifier(u64);

#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
#[serde(rename = "x5u")]
struct X509Url(u64);

#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
#[serde(rename = "x5c")]
struct X509Certificate(u64);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "x5t")]
struct SHA1X509Thumbprint(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "x5t#S256")]
struct SHA256X509Thumbprint(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "typ")]
struct MediaType(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "cty")]
struct ContentType(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "crit")]
struct Critical(Vec<String>);

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Header {
    alg: Algorithm,
    jku: Option<JsonWebKeySetUrl>,
    jwk: Option<JsonWebKey>,
    kid: Option<KeyIdentifier>,
    x5u: Option<X509Url>,
    x5c: Option<X509Certificate>,
    x5t: Option<SHA1X509Thumbprint>,
    x5t_s256: Option<SHA256X509Thumbprint>,
    typ: Option<MediaType>,
    cty: Option<ContentType>,
    crit: Option<Critical>,
}
