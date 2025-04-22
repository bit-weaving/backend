pub struct JwsMint {
    header: JwsHeader,
    signing_key: Option<SigningKey>,
}

impl JwsMint {
    pub fn new(header: JwsHeader) -> Self {
        JwsMint { header, signing_key: todo!() }
    }

    pub fn sign(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
        // Placeholder for actual signing logic
        let mut signature = Vec::new();
        signature.extend_from_slice(data);
        signature.extend_from_slice(key);
        signature
    }
}