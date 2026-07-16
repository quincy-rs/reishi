//! Typed Quinn configuration for KEM-only and hybrid PQ handshakes.

use std::collections::HashSet;
use std::sync::Arc;

use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectError, ConnectionId, crypto};
use reishi_handshake::{Error, HybridKeyPair, HybridPublicKey, PqKeyPair, PqPublicKey};

use crate::initial::compute_retry_tag;
use crate::keys::keys_from_level_secret;
use crate::session::NoiseSession;
use crate::{REISHI_PQ_HYBRID_V1_QUIC_V1, REISHI_PQ_KEM_V1_QUIC_V1};

pub(crate) struct PqNoiseConfig {
    pub(crate) local_keypair: PqKeyPair,
    pub(crate) remote_public: Option<PqPublicKey>,
    pub(crate) prologue: Option<Vec<u8>>,
    pub(crate) allowed_keys: Option<Arc<HashSet<PqPublicKey>>>,
}

/// Quinn client configuration for the KEM-only confirmed `pqIK` suite.
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
        if version != REISHI_PQ_KEM_V1_QUIC_V1 {
            return Err(ConnectError::UnsupportedVersion);
        }

        let mut transport_parameters = Vec::new();
        params.write(&mut transport_parameters);

        Ok(Box::new(NoiseSession::new_pq_initiator(
            &self.inner,
            version,
            transport_parameters,
        )))
    }
}

/// Quinn server configuration for the KEM-only confirmed `pqIK` suite.
pub struct PqNoiseServerConfig {
    inner: Arc<PqNoiseConfig>,
}

impl crypto::ServerConfig for PqNoiseServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        destination_connection_id: &ConnectionId,
    ) -> Result<crypto::Keys, crypto::UnsupportedVersion> {
        if version != REISHI_PQ_KEM_V1_QUIC_V1 {
            return Err(crypto::UnsupportedVersion);
        }

        let level_secret = crate::initial::initial_level_secret(version, destination_connection_id);

        Ok(keys_from_level_secret(false, &level_secret))
    }

    fn retry_tag(
        &self,
        version: u32,
        original_destination_connection_id: &ConnectionId,
        packet: &[u8],
    ) -> [u8; 16] {
        if version != REISHI_PQ_KEM_V1_QUIC_V1 {
            return [0u8; 16];
        }

        compute_retry_tag(original_destination_connection_id, packet)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        if version != REISHI_PQ_KEM_V1_QUIC_V1 {
            return Box::new(NoiseSession::failed());
        }

        let mut transport_parameters = Vec::new();
        params.write(&mut transport_parameters);

        Box::new(NoiseSession::new_pq_responder(
            &self.inner,
            version,
            transport_parameters,
        ))
    }
}

/// Builder for typed KEM-only Quinn client and server configurations.
pub struct PqNoiseConfigBuilder {
    local_keypair: PqKeyPair,
    remote_public: Option<PqPublicKey>,
    prologue: Option<Vec<u8>>,
    allowed_keys: Option<HashSet<PqPublicKey>>,
}

impl PqNoiseConfigBuilder {
    /// Start a KEM-only configuration with the local static keypair.
    pub fn new(local_keypair: PqKeyPair) -> Self {
        Self {
            local_keypair,
            remote_public: None,
            prologue: None,
            allowed_keys: None,
        }
    }

    /// Pin the responder public key required by an initiator.
    pub fn with_remote_public(mut self, key: PqPublicKey) -> Self {
        self.remote_public = Some(key);
        self
    }

    /// Bind application-specific context into the handshake transcript.
    ///
    /// The Quinn integration appends a domain-separated QUIC version binding.
    pub fn with_prologue(mut self, prologue: Vec<u8>) -> Self {
        self.prologue = Some(prologue);
        self
    }

    /// Restrict a responder to the listed authenticated client keys.
    ///
    /// The allowlist is checked only after Message 3 proves possession of the
    /// claimed client secret. Before that check, any client with a valid keypair
    /// can decrypt Message 2, including the responder's non-secret QUIC transport
    /// parameters. Delaying the check prevents unauthenticated allowlist probing.
    /// This setting has no effect on initiator configurations.
    pub fn with_allowed_keys(mut self, keys: impl IntoIterator<Item = PqPublicKey>) -> Self {
        self.allowed_keys = Some(keys.into_iter().collect());
        self
    }

    /// Move builder fields into the shared immutable session configuration.
    fn build_inner(self) -> PqNoiseConfig {
        PqNoiseConfig {
            local_keypair: self.local_keypair,
            remote_public: self.remote_public,
            prologue: self.prologue,
            allowed_keys: self.allowed_keys.map(Arc::new),
        }
    }

    /// Build an initiator configuration, rejecting a missing responder key.
    pub fn build_client_config(self) -> Result<PqNoiseClientConfig, Error> {
        if self.remote_public.is_none() {
            return Err(Error::BadKey);
        }

        Ok(PqNoiseClientConfig {
            inner: Arc::new(self.build_inner()),
        })
    }

    /// Build a responder configuration with an optional client allowlist.
    pub fn build_server_config(self) -> Result<PqNoiseServerConfig, Error> {
        Ok(PqNoiseServerConfig {
            inner: Arc::new(self.build_inner()),
        })
    }
}

pub(crate) struct HybridNoiseConfig {
    pub(crate) local_keypair: HybridKeyPair,
    pub(crate) remote_public: Option<HybridPublicKey>,
    pub(crate) prologue: Option<Vec<u8>>,
    pub(crate) allowed_keys: Option<Arc<HashSet<HybridPublicKey>>>,
}

/// Quinn client configuration for confirmed hybrid classical IK + `pqIK`.
pub struct HybridNoiseClientConfig {
    inner: Arc<HybridNoiseConfig>,
}

impl crypto::ClientConfig for HybridNoiseClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        _server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        if version != REISHI_PQ_HYBRID_V1_QUIC_V1 {
            return Err(ConnectError::UnsupportedVersion);
        }

        let mut transport_parameters = Vec::new();
        params.write(&mut transport_parameters);

        Ok(Box::new(NoiseSession::new_hybrid_initiator(
            &self.inner,
            version,
            transport_parameters,
        )))
    }
}

/// Quinn server configuration for confirmed hybrid classical IK + `pqIK`.
pub struct HybridNoiseServerConfig {
    inner: Arc<HybridNoiseConfig>,
}

impl crypto::ServerConfig for HybridNoiseServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        destination_connection_id: &ConnectionId,
    ) -> Result<crypto::Keys, crypto::UnsupportedVersion> {
        if version != REISHI_PQ_HYBRID_V1_QUIC_V1 {
            return Err(crypto::UnsupportedVersion);
        }

        let level_secret = crate::initial::initial_level_secret(version, destination_connection_id);

        Ok(keys_from_level_secret(false, &level_secret))
    }

    fn retry_tag(
        &self,
        version: u32,
        original_destination_connection_id: &ConnectionId,
        packet: &[u8],
    ) -> [u8; 16] {
        if version != REISHI_PQ_HYBRID_V1_QUIC_V1 {
            return [0u8; 16];
        }

        compute_retry_tag(original_destination_connection_id, packet)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        if version != REISHI_PQ_HYBRID_V1_QUIC_V1 {
            return Box::new(NoiseSession::failed());
        }

        let mut transport_parameters = Vec::new();
        params.write(&mut transport_parameters);

        Box::new(NoiseSession::new_hybrid_responder(
            &self.inner,
            version,
            transport_parameters,
        ))
    }
}

/// Builder for typed hybrid Quinn client and server configurations.
pub struct HybridNoiseConfigBuilder {
    local_keypair: HybridKeyPair,
    remote_public: Option<HybridPublicKey>,
    prologue: Option<Vec<u8>>,
    allowed_keys: Option<HashSet<HybridPublicKey>>,
}

impl HybridNoiseConfigBuilder {
    /// Start a hybrid configuration with the local static keypair.
    pub fn new(local_keypair: HybridKeyPair) -> Self {
        Self {
            local_keypair,
            remote_public: None,
            prologue: None,
            allowed_keys: None,
        }
    }

    /// Pin the responder hybrid public key required by an initiator.
    pub fn with_remote_public(mut self, key: HybridPublicKey) -> Self {
        self.remote_public = Some(key);
        self
    }

    /// Bind application-specific context into the handshake transcript.
    ///
    /// The Quinn integration appends a domain-separated QUIC version binding.
    pub fn with_prologue(mut self, prologue: Vec<u8>) -> Self {
        self.prologue = Some(prologue);
        self
    }

    /// Restrict a responder to the listed authenticated hybrid client keys.
    ///
    /// The allowlist is checked only after Message 3 proves possession of the
    /// claimed client secrets. Before that check, any client with a valid hybrid
    /// keypair can decrypt Message 2, including the responder's non-secret QUIC
    /// transport parameters. Delaying the check prevents unauthenticated
    /// allowlist probing. This setting has no effect on initiator configurations.
    pub fn with_allowed_keys(mut self, keys: impl IntoIterator<Item = HybridPublicKey>) -> Self {
        self.allowed_keys = Some(keys.into_iter().collect());
        self
    }

    /// Move builder fields into the shared immutable session configuration.
    fn build_inner(self) -> HybridNoiseConfig {
        HybridNoiseConfig {
            local_keypair: self.local_keypair,
            remote_public: self.remote_public,
            prologue: self.prologue,
            allowed_keys: self.allowed_keys.map(Arc::new),
        }
    }

    /// Build an initiator configuration, rejecting a missing responder key.
    pub fn build_client_config(self) -> Result<HybridNoiseClientConfig, Error> {
        if self.remote_public.is_none() {
            return Err(Error::BadKey);
        }

        Ok(HybridNoiseClientConfig {
            inner: Arc::new(self.build_inner()),
        })
    }

    /// Build a responder configuration with an optional client allowlist.
    pub fn build_server_config(self) -> Result<HybridNoiseServerConfig, Error> {
        Ok(HybridNoiseServerConfig {
            inner: Arc::new(self.build_inner()),
        })
    }
}
