use serde::Deserialize;
use serde::Serialize;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub enum JwsAlgorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512,
    PS256,
    PS384,
    PS512,
    NONE,
}
impl JwsAlgorithm {
    pub fn from_str(alg: &str) -> Option<Self> {
        match alg {
            "HS256" => Some(JwsAlgorithm::HS256),
            "HS384" => Some(JwsAlgorithm::HS384),
            "HS512" => Some(JwsAlgorithm::HS512),
            "RS256" => Some(JwsAlgorithm::RS256),
            "RS384" => Some(JwsAlgorithm::RS384),
            "RS512" => Some(JwsAlgorithm::RS512),
            "ES256" => Some(JwsAlgorithm::ES256),
            "ES384" => Some(JwsAlgorithm::ES384),
            "ES512" => Some(JwsAlgorithm::ES512),
            "PS256" => Some(JwsAlgorithm::PS256),
            "PS384" => Some(JwsAlgorithm::PS384),
            "PS512" => Some(JwsAlgorithm::PS512),
            "NONE" => Some(JwsAlgorithm::NONE),
            _ => None,
        }
    }

    pub fn to_str(&self) -> &str {
        match self {
            JwsAlgorithm::HS256 => "HS256",
            JwsAlgorithm::HS384 => "HS384",
            JwsAlgorithm::HS512 => "HS512",
            JwsAlgorithm::RS256 => "RS256",
            JwsAlgorithm::RS384 => "RS384",
            JwsAlgorithm::RS512 => "RS512",
            JwsAlgorithm::ES256 => "ES256",
            JwsAlgorithm::ES384 => "ES384",
            JwsAlgorithm::ES512 => "ES512",
            JwsAlgorithm::PS256 => "PS256",
            JwsAlgorithm::PS384 => "PS384",
            JwsAlgorithm::PS512 => "PS512",
            JwsAlgorithm::NONE => "NONE",
        }
    }
}
