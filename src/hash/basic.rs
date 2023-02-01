use {
    base64::{
        encode_config,
        URL_SAFE_NO_PAD,
    },
    crate::Hash,
};
pub struct Basic {
    hash: String,
}
impl From<String> for Basic {
    fn from(input: String) -> Self {
        let hash = encode_config(&input, URL_SAFE_NO_PAD);
        Basic { hash }
    }
}
impl Hash for Basic {
    fn get_hash(&self) -> String {
        self.hash.clone()
    }
}
