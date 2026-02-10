/// Errors that can occur during the Noise handshake or transport phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A cryptographic operation failed (e.g., AEAD decryption, bad DH output).
    CryptoFailed,
    /// A public key is invalid (low-order point, wrong length, etc.).
    BadKey,
    /// The provided output buffer is too small.
    BufferTooSmall,
    /// An operation was attempted in the wrong handshake state.
    WrongState,
    /// The handshake message is malformed or truncated.
    BadMessage,
    /// The nonce counter has been exhausted (2^64 messages sent).
    NonceExhausted,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CryptoFailed => write!(f, "cryptographic operation failed"),
            Self::BadKey => write!(f, "invalid public key"),
            Self::BufferTooSmall => write!(f, "output buffer too small"),
            Self::WrongState => write!(f, "operation not valid in current state"),
            Self::BadMessage => write!(f, "malformed handshake message"),
            Self::NonceExhausted => write!(f, "nonce counter exhausted"),
        }
    }
}

impl core::error::Error for Error {}
