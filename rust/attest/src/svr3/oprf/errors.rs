use std::fmt;

#[derive(Debug)]
pub enum OPRFError {
    ExpandMessageError,
    DeriveKeyPairError,
    BlindError,
}

impl std::error::Error for OPRFError {}

impl fmt::Display for OPRFError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            OPRFError::ExpandMessageError => write!(f, "Expand Message Error"),
            OPRFError::DeriveKeyPairError => write!(f, "Derive Key Pair Error"),
            OPRFError::BlindError => write!(f, "Blinding Error"),
        }
    }
}
