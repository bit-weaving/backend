use crate::{jws::Header, signing_key::SigningKey};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};


pub struct JsonWebSignatureCompact;

impl JsonWebSignatureCompact {


    // A token die component should be used to create multiple tokens using the same state
    pub fn sign<PL: serde::Serialize>(jws_header: Header, payload: PL , signing_key: SigningKey) -> String {
        // Convert the payload to a JSON string
        let payload_json = serde_json::to_string(&payload).unwrap();
        
        // Create the JWS header
        let header_json = serde_json::to_string(&jws_header).unwrap();
        
        // Base64url encode the header and payload
        let encoded_header = BASE64_URL_SAFE_NO_PAD.encode(header_json);
        let encoded_payload = BASE64_URL_SAFE_NO_PAD.encode(payload_json);
        
        // Create the signature
        // this is a placeholder for the actual signing process
        let signature = signing_key.sign(&encoded_header, &encoded_payload);
        
        // Return the JWS compact serialization
        format!("{}.{}.{}", encoded_header, encoded_payload, signature)
        
    }
    
}

pub struct JsonWebSignatureJson;

impl JsonWebSignatureJson {
    pub fn sign<PL: serde::Serialize>(unprotected_header: Option<Header>, protected: Option<Header>, payload: PL , signing_key: SigningKey) -> String {
        // Convert the payload to a JSON string
        let payload_json = serde_json::to_string(&payload).unwrap();
        
        // Create the JWS header
        let header_json = serde_json::to_string(&protected).unwrap();
        
        // Create the signature
        // this is a placeholder for the actual signing process
        let signature = signing_key.sign(&header_json, &payload_json);
        
        // Return the JWS JSON serialization
        format!("{{\"header\": {}, \"payload\": {}, \"signature\": {}}}", header_json, payload_json, signature)
    }

}



pub struct JsonWebEncryption {
    pub header: Header,
    pub payload: String,
    pub ciphertext: String,
    pub iv: String,
    pub tag: String,
}