use {
    base64::{
        decode_config,
        encode_config,
        URL_SAFE_NO_PAD,
    },
    orion::aead,
    crate::{
        Error,
        Hash,
        hash::IntoError,
        Result,
    },
};
const SECRET: &'static str = "LAZY_HASH_SECRET_KEY";
pub struct Secret {
    hash: String,
}
impl Secret {
    pub fn get_secret_from_str(secret_str: &str) -> Result<aead::SecretKey> {
        let secret_dec = decode_config(secret_str, URL_SAFE_NO_PAD).as_err()?;
        let secret = aead::SecretKey::from_slice(secret_dec.as_slice()).as_err()?;
        Ok(secret)
    }
    pub fn get_secret() -> Result<aead::SecretKey> {
        let secret_enc = std::env::var(SECRET).as_err()?;
        Self::get_secret_from_str(&secret_enc)
    }
    pub fn encrypt(secret: &aead::SecretKey, data: &str) -> Result<Self> {
        let encrypted = aead::seal(secret, data.as_bytes()).as_err()?;
        let hash = encode_config(&encrypted, URL_SAFE_NO_PAD);
        Ok(Self { hash })
    }
    pub fn generate_secret_bytes_with_len(len: usize) -> Result<Vec<u8>> {
        let secret = aead::SecretKey::generate(len).as_err()?;
        Ok(secret.unprotected_as_bytes().to_vec())
    }
    pub fn generate_secret_bytes() -> Vec<u8> {
        let secret = aead::SecretKey::default();
        secret.unprotected_as_bytes().to_vec()
    }
    pub fn generate_secret() -> String {
        let bytes = Self::generate_secret_bytes();
        let secret_b64 = encode_config(bytes, URL_SAFE_NO_PAD);
        secret_b64
    }
    pub fn generate_secret_with_len(len: usize) -> Result<String> {
        let bytes = Self::generate_secret_bytes_with_len(len)?;
        let secret_b64 = encode_config(bytes, URL_SAFE_NO_PAD);
        Ok(secret_b64)
    }
    pub fn decrypt(&self) -> Result<String> {
        let secret = Self::get_secret()?;
        let encrypted_bytes = decode_config(&self.hash, URL_SAFE_NO_PAD)
            .as_err()?;
        let decrypted = aead::open(&secret, &encrypted_bytes).as_err()?;
        let decrypted_str = String::from_utf8(decrypted).as_err()?;
        Ok(decrypted_str)
    }
    pub fn decrypt_from(encrypted: &str) -> Result<String> {
        let secret = Self::get_secret()?;
        let encrypted_bytes = decode_config(encrypted, URL_SAFE_NO_PAD)
            .as_err()?;
        let decrypted = aead::open(&secret, &encrypted_bytes).as_err()?;
        let decrypted_str = String::from_utf8(decrypted).as_err()?;
        Ok(decrypted_str)
    }
}
impl TryFrom<String> for Secret {
    type Error = Error;
    fn try_from(input: String) -> Result<Self> {
        let secret = Self::get_secret()?;
        Self::encrypt(&secret, &input)
    }
}
impl Hash for Secret {
    fn get_hash(&self) -> String {
        self.hash.clone()
    }
}
