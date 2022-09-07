pub(crate) mod hash;
pub use hash::{
    basic::Basic,
    Error,
    Hash,
    secret::Secret,
    secure::Secure,
    Result,
};
#[cfg(test)]
mod tests {
    use crate::{
        Basic,
        Hash,
        Secret,
        Secure,
    };
    #[test]
    fn basic_rand() {
        let rand = Basic::rand();
        assert!(rand.is_ok());
        rand.unwrap();
    }
    #[test]
    fn basic_from_string() {
        const HASH_THIS: &'static str = "SomethingToHash";
        let hash = Basic::from_string(HASH_THIS);
        assert!(hash.is_ok());
        hash.unwrap();
    }
    #[test]
    fn secure_rand() {
        let rand = Secure::rand();
        assert!(rand.is_ok());
        rand.unwrap();
    }
    #[test]
    fn secure_from_string() {
        const HASH_THIS: &'static str = "SomethingToHash";
        let secure = Secure::from_string(HASH_THIS);
        assert!(secure.is_ok());
        secure.unwrap();
    }
    #[test]
    fn secure_validate() {
        const HASH_THIS: &'static str = "SomethingToHash";
        let res = Secure::from_string(HASH_THIS);
        assert!(res.is_ok());
        let secure = res.unwrap();
        let valid_res = Secure::validate(HASH_THIS, &secure.get_hash());
        assert!(valid_res.is_ok());
        let is_valid = valid_res.unwrap();
        assert!(is_valid);
    }
    #[test]
    fn secret_get_key() {
        dotenvy::dotenv().unwrap();
        Secret::get_secret().unwrap();
    }
    #[test]
    fn secret_from_string() {
        dotenvy::dotenv().unwrap();
        const ENCRYPTED: &'static str = "SomethingToEncrypt";
        let secret = Secret::from_string(ENCRYPTED).unwrap();
        let decrypted = secret.decrypt().unwrap();
        assert_eq!(ENCRYPTED, decrypted);
    }
}
