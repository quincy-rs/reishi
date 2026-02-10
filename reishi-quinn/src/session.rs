//! Noise IK handshake session implementing `quinn_proto::crypto::Session`.
//!
//! `NoiseSession` drives the reishi-handshake `Handshake` state machine
//! through the two-message IK pattern, framing messages for QUIC's CRYPTO
//! stream and deriving QUIC encryption keys from the handshake output.

use std::any::Any;
use std::sync::Arc;

use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectionId, Side, TransportError, TransportErrorCode, crypto};
use reishi_handshake::HandshakeAction;
use reishi_handshake::crypto::aead::AEAD_TAG_LEN;
use reishi_handshake::crypto::hash::{HASH_LEN, hkdf_expand, hkdf2, hkdf3, hmac};
use zeroize::Zeroize;

use crate::active_handshake::ActiveHandshake;
use crate::framing::HandshakeMessageFramer;
use crate::initial::{initial_level_secret, retry_tag_key};
use crate::keys::{keys_from_level_secret, packet_keys_from_level_secret};
use crate::{ASK_LABEL, NoiseConfig, PeerIdentity};

#[cfg(feature = "pq")]
use crate::pq_config::PqNoiseConfig;

/// TLS alert code for handshake failure (used in QUIC crypto error frames).
const TLS_HANDSHAKE_FAILURE: u8 = 40;

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
        /// The remote peer's static X25519 public key.
        remote_public: [u8; 32],
        /// The final handshake hash.
        handshake_hash: [u8; HASH_LEN],
        /// The remote peer's full hybrid PQ public key (if PQ handshake).
        #[cfg(feature = "pq")]
        remote_pq_public: Option<reishi_handshake::PqPublicKey>,
    },
    /// Handshake fully completed; contains the rekeying secret for
    /// 1-RTT key updates and the handshake hash.
    Completed {
        /// The current 1-RTT rekeying secret. Updated on each `next_1rtt_keys` call.
        rekey_secret: [u8; HASH_LEN],
        /// Secret for `export_keying_material` derivation.
        ekm_secret: [u8; HASH_LEN],
        /// The remote peer's static X25519 public key.
        remote_public: [u8; 32],
        /// The final handshake hash.
        handshake_hash: [u8; HASH_LEN],
        /// The remote peer's full hybrid PQ public key (if PQ handshake).
        #[cfg(feature = "pq")]
        remote_pq_public: Option<reishi_handshake::PqPublicKey>,
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
        }
    }

    /// Create a new initiator (client) session.
    pub(crate) fn new_initiator(config: &Arc<NoiseConfig>, version: u32, params: Vec<u8>) -> Self {
        let handshake = reishi_handshake::Handshake::new_initiator(
            &config.local_keypair,
            config
                .remote_public
                .as_ref()
                .expect("initiator must have remote public key"),
            config.prologue.as_deref().unwrap_or(b""),
        )
        .expect("handshake initialization should succeed with valid keys");

        Self {
            is_initiator: true,
            version,
            state: HandshakeState::InProgress(Box::new(ActiveHandshake::Standard(Box::new(
                handshake,
            )))),
            framer: HandshakeMessageFramer::default(),
            local_params: Some(params),
            peer_params: None,
            handshake_data_ready: false,
        }
    }

    /// Create a new responder (server) session.
    pub(crate) fn new_responder(config: &Arc<NoiseConfig>, version: u32, params: Vec<u8>) -> Self {
        let handshake = reishi_handshake::Handshake::new_responder(
            &config.local_keypair,
            config.prologue.as_deref().unwrap_or(b""),
        )
        .expect("responder handshake initialization should succeed");

        Self {
            is_initiator: false,
            version,
            state: HandshakeState::InProgress(Box::new(ActiveHandshake::Standard(Box::new(
                handshake,
            )))),
            framer: HandshakeMessageFramer::default(),
            local_params: Some(params),
            peer_params: None,
            handshake_data_ready: false,
        }
    }

    /// Create a new PQ initiator (client) session.
    #[cfg(feature = "pq")]
    pub(crate) fn new_pq_initiator(
        config: &Arc<PqNoiseConfig>,
        version: u32,
        params: Vec<u8>,
    ) -> Self {
        let handshake = reishi_handshake::PqHandshake::new_initiator(
            &config.local_keypair,
            config
                .remote_public
                .as_ref()
                .expect("PQ initiator must have remote public key"),
            config.prologue.as_deref().unwrap_or(b""),
        )
        .expect("PQ handshake initialization should succeed with valid keys");

        Self {
            is_initiator: true,
            version,
            state: HandshakeState::InProgress(Box::new(ActiveHandshake::Pq(Box::new(handshake)))),
            framer: HandshakeMessageFramer::default(),
            local_params: Some(params),
            peer_params: None,
            handshake_data_ready: false,
        }
    }

    /// Create a new PQ responder (server) session.
    #[cfg(feature = "pq")]
    pub(crate) fn new_pq_responder(
        config: &Arc<PqNoiseConfig>,
        version: u32,
        params: Vec<u8>,
    ) -> Self {
        let handshake = reishi_handshake::PqHandshake::new_responder(
            &config.local_keypair,
            config.prologue.as_deref().unwrap_or(b""),
        )
        .expect("PQ responder handshake initialization should succeed");

        Self {
            is_initiator: false,
            version,
            state: HandshakeState::InProgress(Box::new(ActiveHandshake::Pq(Box::new(handshake)))),
            framer: HandshakeMessageFramer::default(),
            local_params: Some(params),
            peer_params: None,
            handshake_data_ready: false,
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

            if self.peer_params.is_none() && payload_len > 0 {
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

            if !self.handshake_data_ready {
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
        // Phase 2: write confirmation frame and return Data keys.
        if let HandshakeState::AwaitingDataKeys {
            data_level_secret,
            ekm_secret,
            remote_public,
            handshake_hash,
            #[cfg(feature = "pq")]
            remote_pq_public,
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
            let remote_public = *remote_public;
            let handshake_hash = *handshake_hash;
            #[cfg(feature = "pq")]
            let remote_pq_public = remote_pq_public.clone();

            self.state = HandshakeState::Completed {
                rekey_secret,
                ekm_secret,
                remote_public,
                handshake_hash,
                #[cfg(feature = "pq")]
                remote_pq_public,
            };

            return Ok(Some(data_keys));
        }

        let handshake = match &mut self.state {
            HandshakeState::InProgress(h) => h,
            _ => return Ok(None),
        };

        // Write outgoing Noise message if needed.
        if handshake.next_action() == HandshakeAction::WriteMessage {
            let payload = self.local_params.take().unwrap_or_default();
            let overhead = handshake.next_message_overhead();
            let mut message = vec![0u8; payload.len() + overhead];
            let msg_len = handshake
                .write_message(&payload, &mut message)
                .map_err(|_| Self::crypto_error())?;
            message.truncate(msg_len);

            HandshakeMessageFramer::write_frame(buf, &message).map_err(|_| Self::crypto_error())?;
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

            #[cfg(feature = "pq")]
            let remote_pq_public = handshake.remote_pq_public();

            let remote_public = handshake
                .remote_dh_public_bytes()
                .ok_or_else(Self::crypto_error)?;
            let handshake_hash = *handshake
                .handshake_hash()
                .map_err(|_| Self::crypto_error())?;

            self.state = HandshakeState::AwaitingDataKeys {
                data_level_secret,
                ekm_secret,
                remote_public,
                handshake_hash,
                #[cfg(feature = "pq")]
                remote_pq_public,
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
            HandshakeState::InProgress(h) => {
                let remote = h.remote_dh_public_bytes()?;
                let hash = *h.handshake_hash().ok()?;
                Some(Box::new(PeerIdentity {
                    public_key: remote,
                    handshake_hash: hash,
                    #[cfg(feature = "pq")]
                    pq_public_key: h.remote_pq_public(),
                }))
            }
            HandshakeState::AwaitingDataKeys {
                remote_public,
                handshake_hash,
                #[cfg(feature = "pq")]
                remote_pq_public,
                ..
            } => Some(Box::new(PeerIdentity {
                public_key: *remote_public,
                handshake_hash: *handshake_hash,
                #[cfg(feature = "pq")]
                pq_public_key: remote_pq_public.clone(),
            })),
            HandshakeState::Completed {
                remote_public,
                handshake_hash,
                #[cfg(feature = "pq")]
                remote_pq_public,
                ..
            } => Some(Box::new(PeerIdentity {
                public_key: *remote_public,
                handshake_hash: *handshake_hash,
                #[cfg(feature = "pq")]
                pq_public_key: remote_pq_public.clone(),
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

        // After the Noise handshake completes, the only CRYPTO data we receive
        // is the peer's zero-length confirmation frame. Ignore it gracefully.
        if matches!(
            self.state,
            HandshakeState::Completed { .. } | HandshakeState::AwaitingDataKeys { .. }
        ) {
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

        let key = retry_tag_key(orig_dst_cid);

        let tag_offset = payload.len() - AEAD_TAG_LEN;
        let mut packet = Vec::with_capacity(header.len() + payload.len());
        packet.extend_from_slice(header);
        packet.extend_from_slice(&payload[..tag_offset]);

        let plaintext_len = packet.len();
        packet.extend_from_slice(&[0u8; AEAD_TAG_LEN]);
        if reishi_handshake::crypto::aead::encrypt_in_place(
            &key,
            0,
            b"",
            &mut packet,
            plaintext_len,
        )
        .is_err()
        {
            return false;
        }

        let computed_tag = &packet[plaintext_len..];
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
