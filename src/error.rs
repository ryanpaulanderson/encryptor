//! Error types for authenticated file and key operations.

use std::fmt;
use std::io;

/// Errors returned by the `encryptor` library.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// An operating-system I/O operation failed.
    Io {
        /// The operation being attempted. Paths are deliberately omitted.
        operation: &'static str,
        /// The underlying error, available to callers which explicitly inspect it.
        source: io::Error,
    },
    /// The encrypted input is malformed, noncanonical, or unsupported.
    InvalidFormat(&'static str),
    /// A password does not satisfy the documented byte-length policy.
    InvalidPassword(&'static str),
    /// Authentication, password validation, or signature validation failed.
    AuthenticationFailure,
    /// A checked format, record, or counter limit was exceeded.
    LimitExceeded(&'static str),
    /// The operating-system cryptographic random source failed.
    EntropyFailure,
    /// Argon2 rejected the fixed profile or failed while deriving a key.
    KeyDerivation(argon2::Error),
    /// The final output exists but a post-publication durability operation failed.
    PublishedButNotDurable,
}

impl Error {
    pub(crate) fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}

/// Result type used by this crate.
pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, .. } => write!(f, "I/O error while {operation}"),
            Self::InvalidFormat(message) => write!(f, "invalid encrypted format: {message}"),
            Self::InvalidPassword(message) => write!(f, "invalid password: {message}"),
            Self::AuthenticationFailure => write!(f, "authentication failure"),
            Self::LimitExceeded(message) => write!(f, "security limit exceeded: {message}"),
            Self::EntropyFailure => write!(f, "operating-system random source failed"),
            Self::KeyDerivation(_) => write!(f, "key derivation failed"),
            Self::PublishedButNotDurable => {
                write!(
                    f,
                    "output was published but directory synchronization failed"
                )
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<argon2::Error> for Error {
    fn from(source: argon2::Error) -> Self {
        Self::KeyDerivation(source)
    }
}
