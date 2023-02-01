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
        Error,
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
        input: &'a str, stored: &'a str
    ) -> Result<bool> {
        let stored_bytes = decode_config(stored, URL_SAFE_NO_PAD).as_err()?;
        let stored_hash = String::from_utf8(stored_bytes).as_err()?;
        let is_valid = verify(input, &stored_hash).as_err()?;
        Ok(is_valid)
    }
    pub fn get_salt(&self) -> String {
        self.salt.clone()
    }
}
impl TryFrom<String> for Secure {
    type Error = Error;
    fn try_from(input: String) -> Result<Self> {
        let hash_parts = hash_with_result(&input, Self::COST).as_err()?;
        let salt = hash_parts.get_salt();
        let hash = hash_parts.format_for_version(Self::VERSION);
        let b64 = encode_config(hash, URL_SAFE_NO_PAD);
        return Ok(Secure { hash: b64, salt, });
    }
}
impl Hash for Secure {
    fn get_hash(&self) -> String {
        self.hash.clone()
    }
}
