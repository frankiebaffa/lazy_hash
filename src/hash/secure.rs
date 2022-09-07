use {
    base64::{
        decode_config,
        encode_config,
        URL_SAFE_NO_PAD,
    },
    bcrypt::{
        DEFAULT_COST,
        hash_with_result,
        verify,
        Version,
    },
    crate::{
        Hash,
        hash::IntoError,
        Result,
    },
};
pub struct Secure {
    hash: String,
    salt: String,
}
impl Secure {
    const COST: u32 = DEFAULT_COST;
    const VERSION: Version = Version::TwoB;
    pub fn validate<'a>(
        check: &'a str, against: &'a str
    ) -> Result<bool> {
        let hash_bytes = decode_config(against, URL_SAFE_NO_PAD).as_err()?;
        let stored_hash = String::from_utf8(hash_bytes).as_err()?;
        let is_valid = verify(check, &stored_hash).as_err()?;
        Ok(is_valid)
    }
    pub fn get_salt(&self) -> String {
        self.salt.clone()
    }
}
impl Hash for Secure {
    fn get_hash(&self) -> String {
        self.hash.clone()
    }
    fn from_string<'a>(to_hash: &'a str) -> Result<Self> {
        let hash_parts = hash_with_result(to_hash, Self::COST).as_err()?;
        let salt = hash_parts.get_salt();
        let hash = hash_parts.format_for_version(Self::VERSION);
        let b64 = encode_config(hash, URL_SAFE_NO_PAD);
        return Ok(Secure { hash: b64, salt, });
    }
}
