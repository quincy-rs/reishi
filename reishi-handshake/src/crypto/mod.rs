//! Cryptographic primitives for the Noise IK handshake.
//!
//! - [`aead`]: ChaChaPoly1305 AEAD encryption
//! - [`hash`]: BLAKE2s hashing, HMAC, and HKDF
//! - [`x25519`]: X25519 Diffie-Hellman with low-order point rejection

pub mod aead;
pub mod hash;
#[cfg(feature = "pq")]
pub mod pq;
pub mod x25519;
