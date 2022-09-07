use {
    base64::{
        decode_config,
        encode_config,
        URL_SAFE_NO_PAD,
    },
    orion::aead,
    crate::{
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
    pub fn get_secret() -> Result<aead::SecretKey> {
        let secret_enc = std::env::var(SECRET).as_err()?;
        let secret_dec = decode_config(secret_enc, URL_SAFE_NO_PAD).as_err()?;
        let secret = aead::SecretKey::from_slice(secret_dec.as_slice()).as_err()?;
        Ok(secret)
    }
    pub fn generate_secret() -> Result<String> {
        let secret = aead::SecretKey::default();
        let secret_slice = secret.unprotected_as_bytes();
        let secret_b64 = encode_config(secret_slice, URL_SAFE_NO_PAD);
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
}
impl Hash for Secret {
    fn get_hash(&self) -> String {
        self.hash.clone()
    }
    fn from_string<'a>(input: &'a str) -> Result<Self> {
        let secret = Self::get_secret()?;
        let encrypted = aead::seal(&secret, input.as_bytes()).as_err()?;
        let hash = encode_config(&encrypted, URL_SAFE_NO_PAD);
        Ok(Self { hash })
    }
}
