use {
    base64::{
        decode_config,
        DecodeError,
        encode_config,
        URL_SAFE_NO_PAD,
    },
    bcrypt::{
        DEFAULT_COST,
        BcryptError,
        hash_with_result,
        verify,
        Version,
    },
    std::{
        error::Error as StdError,
        fmt::{
            Display,
            Formatter,
            Result as FmtResult,
        },
        io::Error as IOError,
        result::Result as StdResult,
        string::FromUtf8Error,
    },
    uuid::Uuid,
};
#[derive(Debug)]
pub enum Error {
    BcryptError(BcryptError),
    DecodeError(DecodeError),
    FromUtf8Error(FromUtf8Error),
    IOError(IOError),
}
impl Display for Error {
    fn fmt(&self, fmtr: &mut Formatter) -> FmtResult {
        match self {
            Self::BcryptError(e) => fmtr.write_str(
                &format!("BcryptError: {}", e)
            ),
            Self::DecodeError(e) => fmtr.write_str(
                &format!("DecodeError: {}", e)
            ),
            Self::FromUtf8Error(e) => fmtr.write_str(
                &format!("FromUtf8Error: {}", e)
            ),
            Self::IOError(e) => fmtr.write_str(
                &format!("IOError: {}", e)
            ),
        }
    }
}
impl StdError for Error {}
pub type Result<T> = StdResult<T, Error>;
trait IntoError<T, U>
where
    U: StdError
{
    fn as_err(self) -> Result<T>;
}
impl<T> IntoError<T, BcryptError> for StdResult<T, BcryptError> {
    fn as_err(self) -> Result<T> {
        match self {
            Ok(t) => Ok(t),
            Err(u) => Err(Error::BcryptError(u)),
        }
    }
}
impl<T> IntoError<T, IOError> for StdResult<T, IOError> {
    fn as_err(self) -> Result<T> {
        match self {
            Ok(t) => Ok(t),
            Err(u) => Err(Error::IOError(u)),
        }
    }
}
impl<T> IntoError<T, DecodeError> for StdResult<T, DecodeError> {
    fn as_err(self) -> Result<T> {
        match self {
            Ok(t) => Ok(t),
            Err(u) => Err(Error::DecodeError(u)),
        }
    }
}
impl<T> IntoError<T, FromUtf8Error> for StdResult<T, FromUtf8Error> {
    fn as_err(self) -> Result<T> {
        match self {
            Ok(t) => Ok(t),
            Err(u) => Err(Error::FromUtf8Error(u)),
        }
    }
}
pub trait Hash: Sized {
    fn get_hash(&self) -> String;
    fn from_string<'a>(to_hash: &'a str) -> Result<Self>;
    fn rand() -> Result<Self> {
        let uuid = Uuid::new_v4().to_string();
        Self::from_string(&uuid)
    }
}
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
