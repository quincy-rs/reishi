#![deny(unsafe_code)]

//! # reishi-handshake
//!
//! Pure, sans-IO state machines for classical Noise IK and the optional
//! confirmed KEM-only `pqIK` and hybrid IK + `pqIK` suites.
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
pub mod keys;

mod cipher_state;
mod handshake;
mod symmetric_state;
mod transport;

// Re-export the primary public API
pub use error::Error;
pub use handshake::{Handshake, HandshakeAction, PROTOCOL_NAME};
pub use keys::{KeyPair, PublicKey, StaticSecret};
pub use transport::TransportState;

#[cfg(feature = "pq")]
pub use handshake::{HYBRID_PROTOCOL_NAME, HybridHandshake, PQ_PROTOCOL_NAME, PqHandshake};
#[cfg(feature = "pq")]
pub use keys::{
    EncapsulationKey, HybridKeyPair, HybridPublicKey, HybridStaticSecret, PqKeyPair, PqPublicKey,
    PqStaticSecret,
};
