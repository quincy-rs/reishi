#![deny(unsafe_code)]

//! # reishi-handshake
//!
//! A pure, sans-IO implementation of the Noise IK handshake pattern
//! with a fixed ciphersuite: `Noise_IK_25519_ChaChaPoly_BLAKE2s`.
//!
//! ## Security Properties
//!
//! - X25519 low-order point / identity element rejection
//! - All key material zeroized on drop
//! - Constant-time cryptographic comparisons
//! - No recursive parsing, no panics on network input
//! - Fixed ciphersuite (no algorithm negotiation)

pub mod crypto;
pub mod error;
pub mod types;

mod cipher_state;
mod handshake;
mod symmetric_state;
mod transport;

#[cfg(feature = "pq")]
mod pq_handshake;
#[cfg(feature = "pq")]
pub mod pq_types;

// Re-export the primary public API
pub use error::Error;
pub use handshake::{Handshake, HandshakeAction};
pub use transport::TransportState;
pub use types::{KeyPair, PublicKey, StaticSecret};

#[cfg(feature = "pq")]
pub use pq_handshake::PqHandshake;
#[cfg(feature = "pq")]
pub use pq_types::{PqKeyPair, PqPublicKey, PqStaticSecret};

/// The Noise protocol name for the fixed ciphersuite.
pub const PROTOCOL_NAME: &str = symmetric_state::PROTOCOL_NAME;

/// The Noise protocol name for the hybrid PQ ciphersuite.
#[cfg(feature = "pq")]
pub const PQ_PROTOCOL_NAME: &str = pq_handshake::PQ_PROTOCOL_NAME;
