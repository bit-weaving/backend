use crate::{jws::Header as JwsHeader, signing_key::SigningKey};
pub struct JsonWebSignature {
    
}

impl JsonWebSignature {
    
    pub fn sign(header: JwsHeader, payload: serde::Serialize, signing_key: SigningKey) -> String {
        // Convert the payload to a JSON string
        let payload_json = serde_json::to_string(&payload).unwrap();
        
        // Create the JWS header
        let header_json = serde_json::to_string(&header).unwrap();
        
        // Base64url encode the header and payload
        let encoded_header = base64::encode_config(header_json, base64::URL_SAFE_NO_PAD);
        let encoded_payload = base64::encode_config(payload_json, base64::URL_SAFE_NO_PAD);
        
        // Create the signature
        let signature = signing_key.sign(&encoded_header, &encoded_payload);
        
        // Return the JWS compact serialization
        format!("{}.{}.{}", encoded_header, encoded_payload, signature)
        
    }
    
}


pub struct JsonWebEncryption {
    pub header: Header,
    pub payload: String,
    pub ciphertext: String,
    pub iv: String,
    pub tag: String,
}