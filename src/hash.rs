pub(crate) mod basic;
pub(crate) mod secret;
pub(crate) mod secure;
use {
    base64::DecodeError,
    bcrypt::BcryptError,
    orion::errors::UnknownCryptoError,
    std::{
        error::Error as StdError,
        env::VarError,
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
    UnknownCryptoError(UnknownCryptoError),
    VarError(VarError),
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
            Self::UnknownCryptoError(e) => fmtr.write_str(
                &format!("UnknownCryptoError: {}", e)
            ),
            Self::VarError(e) => fmtr.write_str(
                &format!("VarError: {}", e)
            ),
        }
    }
}
impl StdError for Error {}
pub type Result<T> = StdResult<T, Error>;
pub(crate) trait IntoError<T, U>
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
impl<T> IntoError<T, UnknownCryptoError> for StdResult<T, UnknownCryptoError> {
    fn as_err(self) -> Result<T> {
        match self {
            Ok(t) => Ok(t),
            Err(u) => Err(Error::UnknownCryptoError(u)),
        }
    }
}
impl<T> IntoError<T, VarError> for StdResult<T, VarError> {
    fn as_err(self) -> Result<T> {
        match self {
            Ok(t) => Ok(t),
            Err(u) => Err(Error::VarError(u)),
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
