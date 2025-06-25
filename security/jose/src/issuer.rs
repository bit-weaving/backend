use crate::jws::Header;

/// Multi-tenant broker issuer

pub struct Issuer {
    id: String,
    name: String,
}

pub struct MultiTenantIssuer {
    id: String,
    name: String,
}

pub struct IssuerBuilder {
    id: String,
    name: String,
}

impl IssuerBuilder {
    // Need signing key
    // Need all possible combinations of the JWS Header parameters
    pub fn new(id: String, name: String) -> Self {
        IssuerBuilder { id, name }
    }
}

impl Issuer {
    pub fn sign<PL: serde::Serialize>(payload: PL) -> String {
        // Convert the payload to a JSON string
        let payload_json = serde_json::to_string(&payload).unwrap();
        String::new()

        // Create the JWS header
        // Header needs to be based on issuer configuration
        //let header_json = serde_json::to_string(&protected).unwrap();

        // Create the signature
        // this is a placeholder for the actual signing process
        // Signing Key needs to be based on issuer configuration
        // let signature = signing_key.sign(&header_json, &payload_json);

        // Return the JWS JSON serialization
        /*
        format!(
            "{{\"header\": {}, \"payload\": {}, \"signature\": {}}}",
            header_json, payload_json, signature
        )
         */
    }
}
