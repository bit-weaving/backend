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
            _ => None,
        }
    }
}