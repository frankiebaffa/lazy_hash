use {
    base64::{
        encode_config,
        URL_SAFE_NO_PAD,
    },
    crate::{
        Hash,
        Result,
    },
};
pub struct Basic {
    hash: String,
}
impl Hash for Basic {
    fn get_hash(&self) -> String {
        self.hash.clone()
    }
    fn from_string<'a>(to_hash: &'a str) -> Result<Self> {
        let hash = encode_config(to_hash, URL_SAFE_NO_PAD);
        return Ok(Basic { hash });
    }
}
