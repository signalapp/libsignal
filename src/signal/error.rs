use super::curve;
use prost::DecodeError;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
enum InvalidKeyErrorCause {
    Decode(DecodeError),
    CurveInvalidKey(curve::InvalidKeyError),
}

#[derive(Debug)]
pub struct InvalidKeyError(InvalidKeyErrorCause);

impl Error for InvalidKeyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self.0 {
            InvalidKeyErrorCause::Decode(ref e) => Some(e),
            InvalidKeyErrorCause::CurveInvalidKey(ref e) => Some(e),
        }
    }
}

impl From<DecodeError> for InvalidKeyError {
    fn from(value: DecodeError) -> Self {
        Self(InvalidKeyErrorCause::Decode(value))
    }
}

impl From<curve::InvalidKeyError> for InvalidKeyError {
    fn from(value: curve::InvalidKeyError) -> Self {
        Self(InvalidKeyErrorCause::CurveInvalidKey(value))
    }
}

impl fmt::Display for InvalidKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            InvalidKeyErrorCause::Decode(ref e) => {
                write!(f, "invalid key: failed to decode: {}", e)
            }
            InvalidKeyErrorCause::CurveInvalidKey(ref e) => {
                write!(f, "invalid key: bad ecc key: {}", e)
            }
        }
    }
}
