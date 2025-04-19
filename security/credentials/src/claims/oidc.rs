use serde::Serialize;
use serde::Deserialize;

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "auth_time")]
struct TimeAuthenticated(u64);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "nonce")]
struct Nonce(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "acr")]
struct AuthenticationContextClassReference(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "amr")]
struct AuthenticationMethodsReferences(Vec<String>);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "azp")]
struct AuthorizedParty(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "name")]
struct Name(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "given_name")]
struct GivenName(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "family_name")]
struct FamilyName(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "middle_name")]
struct MiddleName(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "nickname")]
struct Nickname(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "preferred_username")]
struct PreferredUsername(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "profile")]
struct Profile(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "picture")]
struct Picture(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "website")]
struct Website(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "email")]
struct Email(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "email_verified")]
struct VerifiedEmail(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "gender")]
struct Gender(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "birthdate")]
struct Birthdate(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "zoneinfo")]
struct Zoneinfo(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "locale")]
struct Locale(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "phone_number")]
struct PhoneNumber(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "phone_number_verified")]
struct VerifiedPhoneNumber(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "address")]
struct Address {
    formatted: String,
    street_address: String,
    locality: String,
    region: String,
    postal_code: String,
    country: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
#[serde(rename = "updated_at")]
struct UpdatedAt(u64);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "at_hash")]
struct AccessTokenHash(String);

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "c_hash")]
struct CodeHash(String);

// TODO: Need to make this the jwk type rather than a string
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename = "sub_jwk")]
struct SubjectJWK(String);

// TODO: Handle aggregated and distributed claims
// _claim_names
// _claim_sources
// https://openid.net/specs/openid-connect-core-1_0.html#AggregatedDistributedClaims