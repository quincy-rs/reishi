//! PQ Noise IK configuration for quinn.
//!
//! Provides [`PqNoiseConfigBuilder`], [`PqNoiseClientConfig`], and
//! [`PqNoiseServerConfig`] for the hybrid post-quantum handshake mode.
//! These are the PQ counterparts of `NoiseConfigBuilder`, `NoiseClientConfig`,
//! and `NoiseServerConfig`.

use std::sync::Arc;

use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectError, ConnectionId, crypto};
use reishi_handshake::{Error, PqKeyPair, PqPublicKey};

use crate::REISHI_PQ_V1_QUIC_V1;
use crate::initial::compute_retry_tag;
use crate::keys::keys_from_level_secret;
use crate::session::NoiseSession;

/// Shared configuration for PQ client and server sessions.
pub(crate) struct PqNoiseConfig {
    pub(crate) local_keypair: PqKeyPair,
    pub(crate) remote_public: Option<PqPublicKey>,
    pub(crate) prologue: Option<Vec<u8>>,
}

/// PQ Noise IK client (initiator) configuration.
///
/// Implements `quinn_proto::crypto::ClientConfig` to create PQ initiator sessions.
pub struct PqNoiseClientConfig {
    inner: Arc<PqNoiseConfig>,
}

impl crypto::ClientConfig for PqNoiseClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        _server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        if version != REISHI_PQ_V1_QUIC_V1 {
            return Err(ConnectError::UnsupportedVersion);
        }

        let mut transport_params = Vec::new();
        params.write(&mut transport_params);

        let session = NoiseSession::new_pq_initiator(&self.inner, version, transport_params);
        Ok(Box::new(session))
    }
}

/// PQ Noise IK server (responder) configuration.
///
/// Implements `quinn_proto::crypto::ServerConfig` to create PQ responder sessions.
pub struct PqNoiseServerConfig {
    inner: Arc<PqNoiseConfig>,
}

impl crypto::ServerConfig for PqNoiseServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
    ) -> Result<crypto::Keys, crypto::UnsupportedVersion> {
        if version != REISHI_PQ_V1_QUIC_V1 {
            return Err(crypto::UnsupportedVersion);
        }

        let level_secret = crate::initial::initial_level_secret(version, dst_cid);
        Ok(keys_from_level_secret(false, &level_secret))
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        if version != REISHI_PQ_V1_QUIC_V1 {
            return [0u8; 16];
        }

        compute_retry_tag(orig_dst_cid, packet)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        if version != REISHI_PQ_V1_QUIC_V1 {
            return Box::new(NoiseSession::failed());
        }

        let mut transport_params = Vec::new();
        params.write(&mut transport_params);

        let session = NoiseSession::new_pq_responder(&self.inner, version, transport_params);
        Box::new(session)
    }
}

/// Builder for creating [`PqNoiseClientConfig`] and [`PqNoiseServerConfig`].
pub struct PqNoiseConfigBuilder {
    local_keypair: PqKeyPair,
    remote_public: Option<PqPublicKey>,
    prologue: Option<Vec<u8>>,
}

impl PqNoiseConfigBuilder {
    /// Create a new builder with the given local PQ keypair.
    pub fn new(local_keypair: PqKeyPair) -> Self {
        Self {
            local_keypair,
            remote_public: None,
            prologue: None,
        }
    }

    /// Set the remote (server) PQ public key.
    ///
    /// Required for client configurations (the initiator must know the
    /// responder's static key in the IK pattern).
    pub fn with_remote_public(mut self, key: PqPublicKey) -> Self {
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

    fn build_inner(self) -> PqNoiseConfig {
        PqNoiseConfig {
            local_keypair: self.local_keypair,
            remote_public: self.remote_public,
            prologue: self.prologue,
        }
    }

    /// Build a PQ client (initiator) configuration.
    ///
    /// Returns an error if no remote public key was provided (required for IK).
    pub fn build_client_config(self) -> Result<PqNoiseClientConfig, Error> {
        if self.remote_public.is_none() {
            return Err(Error::BadKey);
        }
        Ok(PqNoiseClientConfig {
            inner: Arc::new(self.build_inner()),
        })
    }

    /// Build a PQ server (responder) configuration.
    pub fn build_server_config(self) -> Result<PqNoiseServerConfig, Error> {
        Ok(PqNoiseServerConfig {
            inner: Arc::new(self.build_inner()),
        })
    }
}
