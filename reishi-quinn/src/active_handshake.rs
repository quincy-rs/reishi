//! Handshake dispatch: delegates to either the standard or PQ handshake.
//!
//! When the `pq` feature is enabled, `ActiveHandshake` wraps both
//! `Handshake` (standard IK) and `PqHandshake` (hybrid PQ IK) behind
//! a single uniform interface used by `NoiseSession`.

use reishi_handshake::crypto::hash::HASH_LEN;
use reishi_handshake::{Error, Handshake, HandshakeAction};

#[cfg(feature = "pq")]
use reishi_handshake::{PqHandshake, PqPublicKey};

/// Wraps either a standard or PQ handshake, delegating all calls.
///
/// Both variants are boxed to keep the enum size small. The `ActiveHandshake`
/// itself lives inside `Box<ActiveHandshake>` in `HandshakeState`, so the
/// double-boxing is harmless — it avoids a large size difference between
/// variants (Handshake ~312 bytes vs PqHandshake ~5184 bytes).
pub(crate) enum ActiveHandshake {
    Standard(Box<Handshake>),
    #[cfg(feature = "pq")]
    Pq(Box<PqHandshake>),
}

impl ActiveHandshake {
    pub fn next_action(&self) -> HandshakeAction {
        match self {
            Self::Standard(h) => h.next_action(),
            #[cfg(feature = "pq")]
            Self::Pq(h) => h.next_action(),
        }
    }

    pub fn write_message(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        match self {
            Self::Standard(h) => h.write_message(payload, out),
            #[cfg(feature = "pq")]
            Self::Pq(h) => h.write_message(payload, out),
        }
    }

    pub fn read_message(&mut self, message: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        match self {
            Self::Standard(h) => h.read_message(message, out),
            #[cfg(feature = "pq")]
            Self::Pq(h) => h.read_message(message, out),
        }
    }

    pub fn next_message_overhead(&self) -> usize {
        match self {
            Self::Standard(h) => h.next_message_overhead(),
            #[cfg(feature = "pq")]
            Self::Pq(h) => h.next_message_overhead(),
        }
    }

    pub fn get_ask(&self, label: &[u8]) -> Result<[u8; HASH_LEN], Error> {
        match self {
            Self::Standard(h) => h.get_ask(label),
            #[cfg(feature = "pq")]
            Self::Pq(h) => h.get_ask(label),
        }
    }

    pub fn handshake_hash(&self) -> Result<&[u8; HASH_LEN], Error> {
        match self {
            Self::Standard(h) => h.handshake_hash(),
            #[cfg(feature = "pq")]
            Self::Pq(h) => h.handshake_hash(),
        }
    }

    /// The remote peer's X25519 (DH) static public key bytes.
    pub fn remote_dh_public_bytes(&self) -> Option<[u8; 32]> {
        match self {
            Self::Standard(h) => h.remote_public_bytes(),
            #[cfg(feature = "pq")]
            Self::Pq(h) => h.remote_dh_public_bytes(),
        }
    }

    /// The remote peer's full hybrid PQ public key (PQ mode only).
    #[cfg(feature = "pq")]
    pub fn remote_pq_public(&self) -> Option<PqPublicKey> {
        match self {
            Self::Standard(_) => None,
            Self::Pq(h) => h.remote_public(),
        }
    }
}
