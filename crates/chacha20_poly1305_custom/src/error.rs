//! Error types used by the [`chacha20_poly1305_custom`](crate) crate.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Enable or disable verbose error output for conversions from `std::io::Error`
/// and `argon2::Error`.
///
/// # Examples
///
/// ```
/// chacha20_poly1305_custom::error::set_verbose(true);
/// ```
pub fn set_verbose(val: bool) {
    VERBOSE.store(val, Ordering::Relaxed);
}

/// Errors that can occur when using [`chacha20_poly1305_custom`](crate).
#[derive(Debug)]
pub enum Error {
    /// Underlying I/O error kind when reading or writing files.
    Io(std::io::ErrorKind),
    /// Error produced by the Argon2 library.
    Argon2(argon2::Error),
    /// Authentication tag verification failed during decryption.
    AuthFailure,
    /// Input was malformed or otherwise invalid.
    FormatError(&'static str),
}

/// Convenient `Result` alias used throughout the crate.
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
        if VERBOSE.load(Ordering::Relaxed) {
            eprintln!("DEBUG: {:?}", e);
        }
        Error::Io(e.kind())
    }
}

impl From<argon2::Error> for Error {
    fn from(e: argon2::Error) -> Self {
        if VERBOSE.load(Ordering::Relaxed) {
            eprintln!("DEBUG: {:?}", e);
        }
        Error::Argon2(e)
    }
}
