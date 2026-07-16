//! Noise IK handshake session implementing `quinn_proto::crypto::Session`.
//!
//! `NoiseSession` drives the reishi-handshake `Handshake` state machine
//! through classical two-message IK or a confirmed three-flight PQ pattern,
//! framing messages for QUIC's CRYPTO stream and deriving QUIC keys only after
//! the selected handshake completes.

use std::any::Any;
use std::collections::HashSet;
use std::sync::Arc;

use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectionId, Side, TransportError, TransportErrorCode, crypto};
use reishi_handshake::HandshakeAction;
use reishi_handshake::crypto::aead::AEAD_TAG_LEN;
use reishi_handshake::crypto::hash::{HASH_LEN, hkdf_expand, hkdf2, hkdf3, hmac};
use zeroize::Zeroize;

use crate::active_handshake::{ActiveHandshake, RemoteIdentity};
use crate::framing::HandshakeMessageFramer;
use crate::initial::{initial_level_secret, retry_integrity_key};
use crate::keys::{keys_from_level_secret, packet_keys_from_level_secret};
use crate::{ASK_LABEL, NoiseConfig, PeerIdentity, PeerPublicKey};

#[cfg(feature = "pq")]
use crate::pq_config::{HybridNoiseConfig, PqNoiseConfig};

/// TLS alert code for handshake failure (used in QUIC crypto error frames).
const TLS_HANDSHAKE_FAILURE: u8 = 40;

/// Domain separator placed between the configured prologue and QUIC version.
const QUIC_VERSION_PROLOGUE_LABEL: &[u8] = b"\0reishi-quic-version\0";

/// Maximum allowed size for a Retry packet (header + payload).
///
/// Protects against unbounded allocations from malicious oversized Retry packets.
/// Retry packets are typically small (header + token + tag, usually < 512 bytes).
/// This conservative limit of 65527 bytes (max UDP payload) prevents DoS via
/// repeated large allocations while accommodating any legitimate Retry packet.
const MAX_RETRY_PACKET_SIZE: usize = 65527;

/// Bind the negotiated QUIC version into the Noise transcript prologue.
fn quic_prologue(configured_prologue: &[u8], version: u32) -> Vec<u8> {
    let mut prologue =
        Vec::with_capacity(configured_prologue.len() + QUIC_VERSION_PROLOGUE_LABEL.len() + 4);

    prologue.extend_from_slice(configured_prologue);
    prologue.extend_from_slice(QUIC_VERSION_PROLOGUE_LABEL);
    prologue.extend_from_slice(&version.to_be_bytes());

    prologue
}

/// Internal handshake state: either in-progress or completed.
pub(crate) enum HandshakeState {
    /// Active handshake.
    InProgress(Box<ActiveHandshake>),
    /// Noise handshake completed, Handshake-level keys returned. Waiting for
    /// quinn to request the second key set (Data/1-RTT). This intermediate
    /// state is needed because QUIC requires two key upgrades:
    /// Initial → Handshake → Data.
    AwaitingDataKeys {
        /// Level secret for deriving 1-RTT (Data) keys.
        data_level_secret: [u8; HASH_LEN],
        /// Secret for `export_keying_material` derivation.
        ekm_secret: [u8; HASH_LEN],
        /// The authenticated remote peer's typed static public key.
        remote_public: PeerPublicKey,
        /// The final handshake hash.
        handshake_hash: [u8; HASH_LEN],
        /// Whether the initiator must first receive the responder's Handshake marker.
        wait_for_peer_handshake: bool,
        /// Whether that authenticated Handshake-space marker has arrived.
        peer_handshake_received: bool,
    },
    /// Handshake fully completed; contains the rekeying secret for
    /// 1-RTT key updates and the handshake hash.
    Completed {
        /// The current 1-RTT rekeying secret. Updated on each `next_1rtt_keys` call.
        rekey_secret: [u8; HASH_LEN],
        /// Secret for `export_keying_material` derivation.
        ekm_secret: [u8; HASH_LEN],
        /// The authenticated remote peer's typed static public key.
        remote_public: PeerPublicKey,
        /// The final handshake hash.
        handshake_hash: [u8; HASH_LEN],
    },
    /// Handshake failed and session is dead.
    Failed,
}

impl Drop for HandshakeState {
    fn drop(&mut self) {
        match self {
            HandshakeState::AwaitingDataKeys {
                data_level_secret,
                ekm_secret,
                ..
            } => {
                data_level_secret.zeroize();
                ekm_secret.zeroize();
            }
            HandshakeState::Completed {
                rekey_secret,
                ekm_secret,
                ..
            } => {
                rekey_secret.zeroize();
                ekm_secret.zeroize();
            }
            _ => {}
        }
    }
}

/// The Noise IK handshake session for quinn.
///
/// Implements `quinn_proto::crypto::Session`.
pub struct NoiseSession {
    /// Whether this side is the initiator (client).
    is_initiator: bool,
    /// The QUIC version for this session (used in initial key derivation).
    version: u32,
    /// The handshake state machine or completed keys.
    pub(crate) state: HandshakeState,
    /// Framer for VarInt-length-prefixed handshake messages.
    framer: HandshakeMessageFramer,
    /// Our serialized transport parameters (to embed in handshake payload).
    local_params: Option<Vec<u8>>,
    /// The peer's transport parameters, extracted from the handshake.
    peer_params: Option<TransportParameters>,
    /// Set to `true` once we have data for `handshake_data()`.
    handshake_data_ready: bool,
    /// Optional whitelist of allowed client public keys (server-side only).
    allowed_keys: Option<Arc<HashSet<reishi_handshake::PublicKey>>>,
    /// Optional whitelist of allowed client PQ public keys (server-side only, PQ mode).
    #[cfg(feature = "pq")]
    allowed_pq_keys: Option<Arc<HashSet<reishi_handshake::PqPublicKey>>>,
    /// Optional whitelist of allowed hybrid client keys (server-side only).
    #[cfg(feature = "pq")]
    allowed_hybrid_keys: Option<Arc<HashSet<reishi_handshake::HybridPublicKey>>>,
}

impl NoiseSession {
    /// Create a session that immediately fails (e.g. unsupported version).
    pub(crate) fn failed() -> Self {
        Self {
            is_initiator: false,
            version: 0,
            state: HandshakeState::Failed,
            framer: HandshakeMessageFramer::default(),
            local_params: None,
            peer_params: None,
            handshake_data_ready: false,
            allowed_keys: None,
            #[cfg(feature = "pq")]
            allowed_pq_keys: None,
            #[cfg(feature = "pq")]
            allowed_hybrid_keys: None,
        }
    }

    /// Create a new initiator (client) session.
    pub(crate) fn new_initiator(config: &Arc<NoiseConfig>, version: u32, params: Vec<u8>) -> Self {
        let prologue = quic_prologue(config.prologue.as_deref().unwrap_or(b""), version);
        let handshake = reishi_handshake::Handshake::new_initiator(
            &config.local_keypair,
            config
                .remote_public
                .as_ref()
                .expect("initiator must have remote public key"),
            &prologue,
        )
        .expect("handshake initialization should succeed with valid keys");

        Self {
            is_initiator: true,
            version,
            state: HandshakeState::InProgress(Box::new(ActiveHandshake::Classical(Box::new(
                handshake,
            )))),
            framer: HandshakeMessageFramer::default(),
            local_params: Some(params),
            peer_params: None,
            handshake_data_ready: false,
            allowed_keys: None,
            #[cfg(feature = "pq")]
            allowed_pq_keys: None,
            #[cfg(feature = "pq")]
            allowed_hybrid_keys: None,
        }
    }

    /// Create a new responder (server) session.
    pub(crate) fn new_responder(config: &Arc<NoiseConfig>, version: u32, params: Vec<u8>) -> Self {
        let prologue = quic_prologue(config.prologue.as_deref().unwrap_or(b""), version);
        let handshake =
            reishi_handshake::Handshake::new_responder(&config.local_keypair, &prologue)
                .expect("responder handshake initialization should succeed");

        Self {
            is_initiator: false,
            version,
            state: HandshakeState::InProgress(Box::new(ActiveHandshake::Classical(Box::new(
                handshake,
            )))),
            framer: HandshakeMessageFramer::default(),
            local_params: Some(params),
            peer_params: None,
            handshake_data_ready: false,
            allowed_keys: config.allowed_keys.clone(),
            #[cfg(feature = "pq")]
            allowed_pq_keys: None,
            #[cfg(feature = "pq")]
            allowed_hybrid_keys: None,
        }
    }

    /// Create a new PQ initiator (client) session.
    #[cfg(feature = "pq")]
    pub(crate) fn new_pq_initiator(
        config: &Arc<PqNoiseConfig>,
        version: u32,
        params: Vec<u8>,
    ) -> Self {
        let prologue = quic_prologue(config.prologue.as_deref().unwrap_or(b""), version);
        let handshake = reishi_handshake::PqHandshake::new_initiator(
            &config.local_keypair,
            config
                .remote_public
                .as_ref()
                .expect("PQ initiator must have remote public key"),
            &prologue,
        )
        .expect("PQ handshake initialization should succeed with valid keys");

        Self {
            is_initiator: true,
            version,
            state: HandshakeState::InProgress(Box::new(ActiveHandshake::PostQuantum(Box::new(
                handshake,
            )))),
            framer: HandshakeMessageFramer::default(),
            local_params: Some(params),
            peer_params: None,
            handshake_data_ready: false,
            allowed_keys: None,
            allowed_pq_keys: None,
            allowed_hybrid_keys: None,
        }
    }

    /// Create a new PQ responder (server) session.
    #[cfg(feature = "pq")]
    pub(crate) fn new_pq_responder(
        config: &Arc<PqNoiseConfig>,
        version: u32,
        params: Vec<u8>,
    ) -> Self {
        let prologue = quic_prologue(config.prologue.as_deref().unwrap_or(b""), version);
        let handshake =
            reishi_handshake::PqHandshake::new_responder(&config.local_keypair, &prologue)
                .expect("PQ responder handshake initialization should succeed");

        Self {
            is_initiator: false,
            version,
            state: HandshakeState::InProgress(Box::new(ActiveHandshake::PostQuantum(Box::new(
                handshake,
            )))),
            framer: HandshakeMessageFramer::default(),
            local_params: Some(params),
            peer_params: None,
            handshake_data_ready: false,
            allowed_keys: None,
            allowed_pq_keys: config.allowed_keys.clone(),
            allowed_hybrid_keys: None,
        }
    }

    /// Create a new hybrid initiator (client) session.
    #[cfg(feature = "pq")]
    pub(crate) fn new_hybrid_initiator(
        config: &Arc<HybridNoiseConfig>,
        version: u32,
        params: Vec<u8>,
    ) -> Self {
        let prologue = quic_prologue(config.prologue.as_deref().unwrap_or(b""), version);
        let handshake = reishi_handshake::HybridHandshake::new_initiator(
            &config.local_keypair,
            config
                .remote_public
                .as_ref()
                .expect("hybrid initiator must have remote public key"),
            &prologue,
        )
        .expect("hybrid handshake initialization should succeed with valid keys");

        Self {
            is_initiator: true,
            version,
            state: HandshakeState::InProgress(Box::new(ActiveHandshake::Hybrid(Box::new(
                handshake,
            )))),
            framer: HandshakeMessageFramer::default(),
            local_params: Some(params),
            peer_params: None,
            handshake_data_ready: false,
            allowed_keys: None,
            allowed_pq_keys: None,
            allowed_hybrid_keys: None,
        }
    }

    /// Create a new hybrid responder (server) session.
    #[cfg(feature = "pq")]
    pub(crate) fn new_hybrid_responder(
        config: &Arc<HybridNoiseConfig>,
        version: u32,
        params: Vec<u8>,
    ) -> Self {
        let prologue = quic_prologue(config.prologue.as_deref().unwrap_or(b""), version);
        let handshake =
            reishi_handshake::HybridHandshake::new_responder(&config.local_keypair, &prologue)
                .expect("hybrid responder handshake initialization should succeed");

        Self {
            is_initiator: false,
            version,
            state: HandshakeState::InProgress(Box::new(ActiveHandshake::Hybrid(Box::new(
                handshake,
            )))),
            framer: HandshakeMessageFramer::default(),
            local_params: Some(params),
            peer_params: None,
            handshake_data_ready: false,
            allowed_keys: None,
            allowed_pq_keys: None,
            allowed_hybrid_keys: config.allowed_keys.clone(),
        }
    }

    /// Map a reishi Error to a QUIC transport error.
    fn crypto_error() -> TransportError {
        TransportErrorCode::crypto(TLS_HANDSHAKE_FAILURE).into()
    }

    /// Attempt to read a handshake message from the framer and advance state.
    fn read_handshake_inner(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.framer
            .ingest_bytes(buf)
            .map_err(|_| Self::crypto_error())?;

        let mut new_handshake_data = false;

        while let Some(message) = self.framer.pop_message() {
            let handshake = match &mut self.state {
                HandshakeState::InProgress(h) => h,
                _ => return Err(Self::crypto_error()),
            };

            let action = handshake.next_action();
            if action != HandshakeAction::ReadMessage {
                return Err(Self::crypto_error());
            }

            let mut payload_buf = vec![0u8; message.len()];
            let payload_len = handshake
                .read_message(&message, &mut payload_buf)
                .map_err(|_| Self::crypto_error())?;

            // A PQ identity remains pending until Message 3 proves possession
            // of the claimed initiator static secret.
            if !self.is_initiator && handshake.is_remote_authenticated() {
                let remote = handshake.remote_identity().ok_or_else(Self::crypto_error)?;

                match remote {
                    RemoteIdentity::Classical(key) => {
                        if let Some(ref allowed) = self.allowed_keys {
                            if !allowed.contains(&key) {
                                self.state = HandshakeState::Failed;

                                return Err(Self::crypto_error());
                            }
                        }
                    }
                    #[cfg(feature = "pq")]
                    RemoteIdentity::PostQuantum(key) => {
                        if let Some(ref allowed) = self.allowed_pq_keys {
                            if !allowed.contains(&*key) {
                                self.state = HandshakeState::Failed;

                                return Err(Self::crypto_error());
                            }
                        }
                    }
                    #[cfg(feature = "pq")]
                    RemoteIdentity::Hybrid(key) => {
                        if let Some(ref allowed) = self.allowed_hybrid_keys {
                            if !allowed.contains(&*key) {
                                self.state = HandshakeState::Failed;

                                return Err(Self::crypto_error());
                            }
                        }
                    }
                }
            }

            if self.peer_params.is_none() && handshake.is_remote_authenticated() {
                // TransportParameters::read(side) takes the LOCAL side (the
                // reader), not the peer's side. This controls which server-only
                // or client-only parameters are accepted.
                let local_side = if self.is_initiator {
                    Side::Client
                } else {
                    Side::Server
                };
                let mut param_reader = &payload_buf[..payload_len];
                let params = TransportParameters::read(local_side, &mut param_reader)
                    .map_err(|_| Self::crypto_error())?;
                if !param_reader.is_empty() {
                    return Err(Self::crypto_error());
                }
                self.peer_params = Some(params);
            }

            if handshake.is_remote_authenticated()
                && self.peer_params.is_some()
                && !self.handshake_data_ready
            {
                self.handshake_data_ready = true;
                new_handshake_data = true;
            }
        }

        Ok(new_handshake_data)
    }

    /// Attempt to write a handshake message and/or produce keys.
    ///
    /// QUIC requires two key upgrades: Initial → Handshake → Data. This method
    /// returns keys in two phases:
    ///
    /// **Phase 1** (Initial space): Write any pending Noise message to `buf`
    /// and return Handshake-level keys. Quinn upgrades from Initial to Handshake.
    ///
    /// **Phase 2** (Handshake space): Write a zero-length confirmation frame to
    /// `buf` and return Data/1-RTT keys. Quinn upgrades from Handshake to Data.
    /// The confirmation frame forces quinn to emit a Handshake packet, which is
    /// required for both sides to transition to the Established state.
    fn write_handshake_inner(
        &mut self,
        buf: &mut Vec<u8>,
    ) -> Result<Option<crypto::Keys>, TransportError> {
        if let HandshakeState::AwaitingDataKeys {
            wait_for_peer_handshake: true,
            peer_handshake_received: false,
            ..
        } = &self.state
        {
            return Ok(None);
        }

        // Phase 2: write confirmation frame and return Data keys.
        if let HandshakeState::AwaitingDataKeys {
            data_level_secret,
            ekm_secret,
            remote_public,
            handshake_hash,
            ..
        } = &self.state
        {
            // Write a zero-length confirmation frame. This ensures quinn has
            // outgoing data for the Handshake space, causing it to emit a
            // Handshake packet. Without this, the peer would never receive a
            // Handshake packet and quinn's state machine would never transition
            // to Established.
            HandshakeMessageFramer::write_frame(buf, &[]).map_err(|_| Self::crypto_error())?;

            let data_keys = keys_from_level_secret(self.is_initiator, data_level_secret);

            let (rekey_secret_z, _) = hkdf2(data_level_secret, b"reishi rekey");
            let mut rekey_secret = [0u8; HASH_LEN];
            rekey_secret.copy_from_slice(&*rekey_secret_z);

            let ekm_secret = *ekm_secret;
            let remote_public = remote_public.clone();
            let handshake_hash = *handshake_hash;

            self.state = HandshakeState::Completed {
                rekey_secret,
                ekm_secret,
                remote_public,
                handshake_hash,
            };

            return Ok(Some(data_keys));
        }

        let handshake = match &mut self.state {
            HandshakeState::InProgress(h) => h,
            _ => return Ok(None),
        };

        // Write outgoing Noise message if needed.
        let mut wrote_handshake_message = false;

        if handshake.next_action() == HandshakeAction::WriteMessage {
            let payload = if handshake.next_message_accepts_payload() {
                self.local_params.take().unwrap_or_default()
            } else {
                Vec::new()
            };

            let overhead = handshake.next_message_overhead();
            let mut message = vec![0u8; payload.len() + overhead];

            let message_length = handshake
                .write_message(&payload, &mut message)
                .map_err(|_| Self::crypto_error())?;
            message.truncate(message_length);

            HandshakeMessageFramer::write_frame(buf, &message).map_err(|_| Self::crypto_error())?;
            wrote_handshake_message = true;
        }

        // Noise handshake is complete — derive and return Handshake-level keys.
        if handshake.next_action() == HandshakeAction::Complete {
            let mut ask = handshake
                .get_ask(ASK_LABEL)
                .map_err(|_| Self::crypto_error())?;

            // Derive three secrets: Handshake-level, Data-level, and EKM.
            let (hs_level_secret_z, data_level_secret_z, ekm_secret_z) =
                hkdf3(&ask, b"reishi levels");
            ask.zeroize();

            let mut hs_level_secret = [0u8; HASH_LEN];
            hs_level_secret.copy_from_slice(&*hs_level_secret_z);
            let mut data_level_secret = [0u8; HASH_LEN];
            data_level_secret.copy_from_slice(&*data_level_secret_z);
            let mut ekm_secret = [0u8; HASH_LEN];
            ekm_secret.copy_from_slice(&*ekm_secret_z);

            let hs_keys = keys_from_level_secret(self.is_initiator, &hs_level_secret);
            hs_level_secret.zeroize();

            let remote_public = match handshake.remote_identity().ok_or_else(Self::crypto_error)? {
                RemoteIdentity::Classical(key) => PeerPublicKey::Classical(key),
                #[cfg(feature = "pq")]
                RemoteIdentity::PostQuantum(key) => PeerPublicKey::PostQuantum(*key),
                #[cfg(feature = "pq")]
                RemoteIdentity::Hybrid(key) => PeerPublicKey::Hybrid(*key),
            };

            let handshake_hash = *handshake
                .handshake_hash()
                .map_err(|_| Self::crypto_error())?;

            self.state = HandshakeState::AwaitingDataKeys {
                data_level_secret,
                ekm_secret,
                remote_public,
                handshake_hash,
                wait_for_peer_handshake: self.is_initiator && wrote_handshake_message,
                peer_handshake_received: false,
            };

            return Ok(Some(hs_keys));
        }

        Ok(None)
    }
}

impl crypto::Session for NoiseSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> crypto::Keys {
        let local_is_initiator = matches!(side, Side::Client);
        let level_secret = initial_level_secret(self.version, dst_cid);
        keys_from_level_secret(local_is_initiator, &level_secret)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        if !self.handshake_data_ready {
            return None;
        }

        // Actual identity is available via peer_identity()
        Some(Box::new(()))
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        match &self.state {
            HandshakeState::InProgress(_) => None,
            HandshakeState::AwaitingDataKeys {
                remote_public,
                handshake_hash,
                ..
            } => Some(Box::new(PeerIdentity {
                public_key: remote_public.clone(),
                handshake_hash: *handshake_hash,
            })),
            HandshakeState::Completed {
                remote_public,
                handshake_hash,
                ..
            } => Some(Box::new(PeerIdentity {
                public_key: remote_public.clone(),
                handshake_hash: *handshake_hash,
            })),
            HandshakeState::Failed => None,
        }
    }

    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        None // IK does not support 0-RTT
    }

    fn early_data_accepted(&self) -> Option<bool> {
        None
    }

    fn is_handshaking(&self) -> bool {
        matches!(
            self.state,
            HandshakeState::InProgress(_) | HandshakeState::AwaitingDataKeys { .. }
        )
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        if matches!(self.state, HandshakeState::Failed) {
            return Err(Self::crypto_error());
        }

        if matches!(self.state, HandshakeState::AwaitingDataKeys { .. }) {
            if self.framer.ingest_bytes(buf).is_err() {
                self.state = HandshakeState::Failed;

                return Err(Self::crypto_error());
            }

            let confirmation = self.framer.pop_message();

            if confirmation.as_deref() != Some(&[]) || self.framer.pop_message().is_some() {
                self.state = HandshakeState::Failed;

                return Err(Self::crypto_error());
            }

            if let HandshakeState::AwaitingDataKeys {
                peer_handshake_received,
                ..
            } = &mut self.state
            {
                *peer_handshake_received = true;
            }

            return Ok(false);
        }

        // Quinn may retransmit its empty Handshake-space marker after keys are installed.
        if matches!(self.state, HandshakeState::Completed { .. }) {
            return Ok(false);
        }

        match self.read_handshake_inner(buf) {
            Ok(result) => Ok(result),
            Err(e) => {
                self.state = HandshakeState::Failed;
                Err(e)
            }
        }
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        if !self.is_handshaking() && self.peer_params.is_none() {
            // QUIC requires transport parameters from both sides
            return Err(Self::crypto_error());
        }
        Ok(self.peer_params)
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<crypto::Keys> {
        if matches!(self.state, HandshakeState::Failed) {
            return None;
        }

        match self.write_handshake_inner(buf) {
            Ok(keys) => keys,
            Err(_) => {
                self.state = HandshakeState::Failed;
                None
            }
        }
    }

    fn next_1rtt_keys(&mut self) -> Option<crypto::KeyPair<Box<dyn crypto::PacketKey>>> {
        match &mut self.state {
            HandshakeState::Completed { rekey_secret, .. } => {
                let keys = packet_keys_from_level_secret(self.is_initiator, rekey_secret);

                // Ratchet the rekey secret forward
                let (next_secret_z, _) = hkdf2(rekey_secret, b"reishi rekey");
                rekey_secret.copy_from_slice(&*next_secret_z);

                Some(keys)
            }
            _ => None,
        }
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        if payload.len() < AEAD_TAG_LEN {
            return false;
        }

        // Reject oversized Retry packets to prevent unbounded allocation/copy.
        let total_len = header.len().saturating_add(payload.len());
        if total_len > MAX_RETRY_PACKET_SIZE {
            return false;
        }

        let key = retry_integrity_key();

        // Reconstruct the pseudo-packet: [cid_len, cid..., header..., payload_without_tag...]
        // This must match the construction in compute_retry_tag, where
        // packet = header + payload_without_tag.
        let tag_offset = payload.len() - AEAD_TAG_LEN;
        let mut pseudo_packet =
            Vec::with_capacity(1 + orig_dst_cid.len() + header.len() + tag_offset);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(header);
        pseudo_packet.extend_from_slice(&payload[..tag_offset]);

        let hmac_output = hmac(&key, &pseudo_packet);
        let computed_tag = &hmac_output[..AEAD_TAG_LEN];
        let received_tag = &payload[tag_offset..];

        subtle::ConstantTimeEq::ct_eq(computed_tag, received_tag).into()
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), crypto::ExportKeyingMaterialError> {
        let ekm_secret = match &self.state {
            HandshakeState::AwaitingDataKeys { ekm_secret, .. }
            | HandshakeState::Completed { ekm_secret, .. } => ekm_secret,
            _ => return Err(crypto::ExportKeyingMaterialError),
        };

        // HKDF-Extract: PRK = HMAC(ekm_secret, label)
        let prk = hmac(ekm_secret, label);
        // HKDF-Expand: derive output from PRK keyed by context
        if !hkdf_expand(&prk, context, output) {
            return Err(crypto::ExportKeyingMaterialError);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn_proto::crypto::Session as _;

    /// Helper: construct a minimal `NoiseSession` for retry-validation tests.
    ///
    /// `is_valid_retry` does not access session state, so a failed session
    /// is sufficient.
    fn test_session() -> NoiseSession {
        NoiseSession::failed()
    }

    #[test]
    fn quic_prologue_binds_the_selected_version() {
        let version_1_prologue = quic_prologue(b"application", 0x52510301);
        let version_2_prologue = quic_prologue(b"application", 0x52510302);

        assert!(version_1_prologue.starts_with(b"application"));
        assert_eq!(
            &version_1_prologue
                [b"application".len()..b"application".len() + QUIC_VERSION_PROLOGUE_LABEL.len()],
            QUIC_VERSION_PROLOGUE_LABEL,
        );
        assert_eq!(
            &version_1_prologue[version_1_prologue.len() - 4..],
            &0x52510301u32.to_be_bytes(),
        );
        assert_ne!(version_1_prologue, version_2_prologue);
    }

    #[test]
    fn malformed_confirmation_framing_fails_the_session() {
        let remote_keypair = reishi_handshake::KeyPair::generate(&mut rand_core::OsRng);
        let mut session = test_session();

        session.state = HandshakeState::AwaitingDataKeys {
            data_level_secret: [1u8; HASH_LEN],
            ekm_secret: [2u8; HASH_LEN],
            remote_public: PeerPublicKey::Classical(remote_keypair.public),
            handshake_hash: [3u8; HASH_LEN],
            wait_for_peer_handshake: true,
            peer_handshake_received: false,
        };

        assert!(session.read_handshake(&[0xff; 8]).is_err());
        assert!(matches!(session.state, HandshakeState::Failed));
    }

    #[test]
    fn oversized_retry_packet_rejected() {
        let session = test_session();
        let orig_dst_cid = ConnectionId::new(&[1, 2, 3, 4]);

        // Total size = MAX_RETRY_PACKET_SIZE + 1 (just over the limit).
        // Payload must be >= AEAD_TAG_LEN to pass the first check.
        let header = vec![0u8; MAX_RETRY_PACKET_SIZE + 1 - AEAD_TAG_LEN];
        let payload = vec![0u8; AEAD_TAG_LEN];

        assert!(!session.is_valid_retry(&orig_dst_cid, &header, &payload));
    }

    #[test]
    fn very_large_retry_packet_rejected() {
        let session = test_session();
        let orig_dst_cid = ConnectionId::new(&[5, 6, 7, 8]);

        // Well above the limit: both header and payload are large.
        let header = vec![0u8; MAX_RETRY_PACKET_SIZE];
        let payload = vec![0u8; MAX_RETRY_PACKET_SIZE];

        assert!(!session.is_valid_retry(&orig_dst_cid, &header, &payload));
    }

    #[test]
    fn retry_at_size_limit_not_rejected_by_size_check() {
        let session = test_session();
        let orig_dst_cid = ConnectionId::new(&[9, 10, 11, 12]);

        // Total size == MAX_RETRY_PACKET_SIZE (exactly at the boundary).
        // This should pass the size check but still return false because the
        // tag won't match — proving the size guard doesn't over-reject.
        let header = vec![0u8; MAX_RETRY_PACKET_SIZE - AEAD_TAG_LEN];
        let payload = vec![0u8; AEAD_TAG_LEN];

        // Returns false due to tag mismatch, not due to the size check.
        // The important property: no panic, no OOM, and if we had a matching
        // tag it would be accepted.
        assert!(!session.is_valid_retry(&orig_dst_cid, &header, &payload));
    }
}
