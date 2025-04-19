use serde::Serialize;
use serde::Deserialize;

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "iss")]
struct Issuer(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "sub")]
struct Subject(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "aud")]
struct Audience(String);

#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
#[serde(rename = "exp")]
struct Expires(u64);

#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
#[serde(rename = "nbf")]
struct NotBefore(u64);

#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
#[serde(rename = "iat")]
struct IssuedAt(u64);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "jti")]
struct JwtTokenId(String);
