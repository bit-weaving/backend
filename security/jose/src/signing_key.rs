pub struct SigningKey {

}
/*
- ECC and RSA Keys are different types of keys that can made 
the same via conversion to PKCS#8 format.
- PKCS#8 is a standard for encoding private keys in a portable format.
- PKCS#8 keys can be used with different cryptographic algorithms,


The option is to require developers to know which public or private key
format they need to be using.
 */