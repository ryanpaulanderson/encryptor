use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(std::io::ErrorKind),
    Argon2(argon2::Error),
    AuthFailure,
    FormatError(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(kind) => write!(f, "I/O error: {:?}", kind),
            Error::Argon2(_) => write!(f, "argon2 error"),
            Error::AuthFailure => write!(f, "authentication failure"),
            Error::FormatError(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.kind())
    }
}

impl From<argon2::Error> for Error {
    fn from(e: argon2::Error) -> Self {
        Error::Argon2(e)
    }
}
