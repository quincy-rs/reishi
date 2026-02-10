#![deny(unsafe_code)]

//! # reishi-quinn
//!
//! Integration of the [`reishi-handshake`] Noise IK handshake with
//! `quinn-proto`'s crypto traits, enabling Noise-over-QUIC.
//!
//! This crate provides:
//!
//! - [`NoiseClientConfig`] implementing `quinn_proto::crypto::ClientConfig`
//! - [`NoiseServerConfig`] implementing `quinn_proto::crypto::ServerConfig`
//! - [`NoiseConfigBuilder`] for constructing configs from keypairs
//! - All necessary key types (`PacketKey`, `HeaderKey`, `HmacKey`, etc.)
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use reishi_quinn::{NoiseConfigBuilder, KeyPair};
//! use rand_core::OsRng;
//!
//! let server_keypair = KeyPair::generate(&mut OsRng);
//! let server_public = server_keypair.public;
//!
//! // Server config
//! let server_config = NoiseConfigBuilder::new(server_keypair)
//!     .build_server_config()
//!     .unwrap();
//!
//! // Client config (needs server's public key)
//! let client_keypair = KeyPair::generate(&mut OsRng);
//! let client_config = NoiseConfigBuilder::new(client_keypair)
//!     .with_remote_public(server_public)
//!     .build_client_config()
//!     .unwrap();
//! ```

pub mod framing;
pub mod initial;
pub mod keys;
pub mod session;
pub mod token;

pub(crate) mod active_handshake;

#[cfg(feature = "pq")]
pub mod pq_config;

// Re-export key types from reishi-handshake for convenience.
pub use reishi_handshake::{Error, KeyPair, PROTOCOL_NAME, PublicKey, StaticSecret};

#[cfg(feature = "pq")]
pub use reishi_handshake::{PQ_PROTOCOL_NAME, PqKeyPair, PqPublicKey, PqStaticSecret};

#[cfg(feature = "pq")]
pub use pq_config::{PqNoiseClientConfig, PqNoiseConfigBuilder, PqNoiseServerConfig};

use std::sync::Arc;

use crate::initial::compute_retry_tag;
use crate::keys::keys_from_level_secret;
use crate::session::NoiseSession;
use crate::token::{NoiseHandshakeTokenKey, NoiseHmacKey};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectError, ConnectionId, crypto};

/// Custom QUIC version number for Reishi v1 over QUIC v1.
///
/// Encodes as `"RQ\x01\x01"` in the version field.
pub const REISHI_V1_QUIC_V1: u32 = 0x52510101;

/// Custom QUIC version number for Reishi PQ v1 over QUIC v1.
///
/// Encodes as `"RQ\x02\x01"` in the version field.
#[cfg(feature = "pq")]
pub const REISHI_PQ_V1_QUIC_V1: u32 = 0x52510201;

/// Label used to derive initial-level secrets from the client's DCID.
pub const INITIAL_LABEL: &[u8] = b"reishi initial";

/// Label used to derive the retry tag key.
pub const RETRY_LABEL: &[u8] = b"reishi retry";

/// Label for deriving initiator header protection subkeys.
pub const INIT_HP_LABEL: &[u8] = b"init hp";

/// Label for deriving responder header protection subkeys.
pub const RESP_HP_LABEL: &[u8] = b"resp hp";

/// Label for deriving initiator packet data subkeys.
pub const INIT_DATA_LABEL: &[u8] = b"init data";

/// Label for deriving responder packet data subkeys.
pub const RESP_DATA_LABEL: &[u8] = b"resp data";

/// ASK label used to extract the level secret from the Noise handshake.
pub const ASK_LABEL: &[u8] = b"reishi key";

/// Peer identity extracted after a successful Noise IK handshake.
///
/// Available via `Connection::peer_identity()` after the handshake completes.
/// Downcast the `Box<dyn Any>` to this type.
#[derive(Debug, Clone)]
pub struct PeerIdentity {
    /// The peer's static X25519 public key (32 bytes).
    pub public_key: [u8; 32],
    /// The final Noise handshake hash (channel binding value, 32 bytes).
    pub handshake_hash: [u8; 32],
    /// The peer's full hybrid PQ public key (if PQ handshake).
    #[cfg(feature = "pq")]
    pub pq_public_key: Option<reishi_handshake::PqPublicKey>,
}

/// Shared configuration for both client and server sessions.
pub(crate) struct NoiseConfig {
    pub(crate) local_keypair: KeyPair,
    pub(crate) remote_public: Option<PublicKey>,
    pub(crate) prologue: Option<Vec<u8>>,
}

/// Noise IK client (initiator) configuration.
///
/// Implements `quinn_proto::crypto::ClientConfig` to create initiator sessions.
pub struct NoiseClientConfig {
    inner: Arc<NoiseConfig>,
}

impl crypto::ClientConfig for NoiseClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        _server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        if version != REISHI_V1_QUIC_V1 {
            return Err(ConnectError::UnsupportedVersion);
        }

        let mut transport_params = Vec::new();
        params.write(&mut transport_params);

        let session = NoiseSession::new_initiator(&self.inner, version, transport_params);
        Ok(Box::new(session))
    }
}

/// Noise IK server (responder) configuration.
///
/// Implements `quinn_proto::crypto::ServerConfig` to create responder sessions,
/// derive initial keys, and compute retry tags.
pub struct NoiseServerConfig {
    inner: Arc<NoiseConfig>,
}

impl crypto::ServerConfig for NoiseServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
    ) -> Result<crypto::Keys, crypto::UnsupportedVersion> {
        if version != REISHI_V1_QUIC_V1 {
            return Err(crypto::UnsupportedVersion);
        }

        let level_secret = initial::initial_level_secret(version, dst_cid);
        Ok(keys_from_level_secret(false, &level_secret))
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        if version != REISHI_V1_QUIC_V1 {
            return [0u8; 16];
        }

        compute_retry_tag(orig_dst_cid, packet)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        if version != REISHI_V1_QUIC_V1 {
            return Box::new(NoiseSession::failed());
        }

        let mut transport_params = Vec::new();
        params.write(&mut transport_params);

        let session = NoiseSession::new_responder(&self.inner, version, transport_params);
        Box::new(session)
    }
}

/// Builder for creating [`NoiseClientConfig`] and [`NoiseServerConfig`].
///
/// # Example
///
/// ```rust,no_run
/// use reishi_quinn::{NoiseConfigBuilder, KeyPair, PublicKey};
/// use rand_core::OsRng;
///
/// let keypair = KeyPair::generate(&mut OsRng);
/// let server_pub = PublicKey::from_bytes([0u8; 32]); // placeholder
///
/// let client = NoiseConfigBuilder::new(keypair)
///     .with_remote_public(server_pub)
///     .build_client_config()
///     .unwrap();
/// ```
pub struct NoiseConfigBuilder {
    local_keypair: KeyPair,
    remote_public: Option<PublicKey>,
    prologue: Option<Vec<u8>>,
}

impl NoiseConfigBuilder {
    /// Create a new builder with the given local keypair.
    pub fn new(local_keypair: KeyPair) -> Self {
        Self {
            local_keypair,
            remote_public: None,
            prologue: None,
        }
    }

    /// Set the remote (server) public key.
    ///
    /// Required for client configurations (the initiator must know the
    /// responder's static key in the IK pattern).
    pub fn with_remote_public(mut self, key: PublicKey) -> Self {
        self.remote_public = Some(key);
        self
    }

    /// Set a custom prologue for the handshake.
    ///
    /// Both sides must use the same prologue for the handshake to succeed.
    /// Defaults to empty.
    pub fn with_prologue(mut self, prologue: Vec<u8>) -> Self {
        self.prologue = Some(prologue);
        self
    }

    /// Build the shared inner config.
    fn build_inner(self) -> NoiseConfig {
        NoiseConfig {
            local_keypair: self.local_keypair,
            remote_public: self.remote_public,
            prologue: self.prologue,
        }
    }

    /// Build a client (initiator) configuration.
    ///
    /// Returns an error if no remote public key was provided (required for IK).
    pub fn build_client_config(self) -> Result<NoiseClientConfig, Error> {
        if self.remote_public.is_none() {
            return Err(Error::BadKey);
        }
        Ok(NoiseClientConfig {
            inner: Arc::new(self.build_inner()),
        })
    }

    /// Build a server (responder) configuration.
    pub fn build_server_config(self) -> Result<NoiseServerConfig, Error> {
        Ok(NoiseServerConfig {
            inner: Arc::new(self.build_inner()),
        })
    }
}

/// Create a `NoiseHmacKey` for use with `quinn_proto::EndpointConfig`.
///
/// This is needed for stateless reset token generation.
pub fn noise_hmac_key() -> Arc<dyn crypto::HmacKey> {
    Arc::new(NoiseHmacKey::new())
}

/// Create a `NoiseHandshakeTokenKey` for use with `quinn::ServerConfig`.
///
/// This is needed for address validation token generation.
pub fn noise_handshake_token_key() -> Arc<dyn crypto::HandshakeTokenKey> {
    Arc::new(NoiseHandshakeTokenKey::new())
}
