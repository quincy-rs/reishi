//! Confirmed KEM-only `pqIK` handshake.
//!
//! ```text
//! <- s_kem
//! ...
//! -> skem_r, ENC(e_kem_i, s_kem_i)
//! <- ekem_i, ENC(skem_i), payload_r
//! -> ENC(confirm, payload_i)
//! ```

use rand_core::{CryptoRngCore, OsRng};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::aead::AEAD_TAG_LEN;
use crate::crypto::hash::{self, HASH_LEN};
use crate::crypto::pq::{self, KEM_CT_LEN, KEM_EK_LEN, KEM_SEED_LEN};
use crate::error::Error;
use crate::handshake::standard::HandshakeAction;
use crate::keys::pq::{EncapsulationKey, PqKeyPair, PqPublicKey};
use crate::symmetric_state::SymmetricState;
use crate::transport::TransportState;

/// Transcript name for the fixed confirmed KEM-only ciphersuite.
pub const PQ_PROTOCOL_NAME: &str = "Noise_pqIKkc_MLKEM768_ChaChaPoly_BLAKE2s";
/// Largest handshake message accepted or emitted by the state machine.
pub const MAX_MESSAGE_LEN: usize = 65535;

/// Fixed Message 1 overhead; application payload is forbidden in this flight.
pub const MSG1_OVERHEAD: usize = KEM_CT_LEN + (2 * KEM_EK_LEN) + AEAD_TAG_LEN;
/// Fixed Message 2 overhead before the responder payload.
pub const MSG2_OVERHEAD: usize = KEM_CT_LEN + KEM_CT_LEN + AEAD_TAG_LEN + AEAD_TAG_LEN;
/// Fixed Message 3 confirmation overhead before the initiator payload.
pub const MSG3_OVERHEAD: usize = AEAD_TAG_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    InitiatorWriteMessage1,
    InitiatorReadMessage2,
    InitiatorWriteMessage3,
    ResponderReadMessage1,
    ResponderWriteMessage2,
    ResponderReadMessage3,
    Complete,
}

/// State machine for the confirmed KEM-only `pqIK` pattern.
///
/// The responder intentionally keeps the claimed initiator identity pending
/// until Message 3 proves possession of the matching ML-KEM secret.
pub struct PqHandshake {
    symmetric: Option<SymmetricState>,
    phase: Phase,
    is_initiator: bool,
    remote_authenticated: bool,

    static_kem_seed: Zeroizing<[u8; KEM_SEED_LEN]>,
    static_kem_public: [u8; KEM_EK_LEN],
    seec_key: Zeroizing<[u8; 32]>,
    remote_static_kem_public: Option<[u8; KEM_EK_LEN]>,
    remote_ephemeral_kem_public: Option<[u8; KEM_EK_LEN]>,
    ephemeral_kem_seed: Option<Zeroizing<[u8; KEM_SEED_LEN]>>,
}

impl Drop for PqHandshake {
    fn drop(&mut self) {
        self.static_kem_public.zeroize();

        if let Some(remote_static) = &mut self.remote_static_kem_public {
            remote_static.zeroize();
        }

        if let Some(remote_ephemeral) = &mut self.remote_ephemeral_kem_public {
            remote_ephemeral.zeroize();
        }
    }
}

impl PqHandshake {
    /// Start an initiator handshake with the responder's pinned static KEM key.
    pub fn new_initiator(
        local: &PqKeyPair,
        remote_public: &PqPublicKey,
        prologue: &[u8],
    ) -> Result<Self, Error> {
        let mut symmetric = SymmetricState::initialize(PQ_PROTOCOL_NAME);
        symmetric.mix_hash(prologue);
        symmetric.mix_hash(remote_public.kem_ek.as_bytes());

        Ok(Self {
            symmetric: Some(symmetric),
            phase: Phase::InitiatorWriteMessage1,
            is_initiator: true,
            remote_authenticated: false,
            static_kem_seed: local.secret.kem_seed.clone(),
            static_kem_public: *local.public.kem_ek.as_bytes(),
            seec_key: local.secret.seec_key.clone(),
            remote_static_kem_public: Some(*remote_public.kem_ek.as_bytes()),
            remote_ephemeral_kem_public: None,
            ephemeral_kem_seed: None,
        })
    }

    /// Start a responder handshake without assuming an initiator identity.
    pub fn new_responder(local: &PqKeyPair, prologue: &[u8]) -> Result<Self, Error> {
        let mut symmetric = SymmetricState::initialize(PQ_PROTOCOL_NAME);
        symmetric.mix_hash(prologue);
        symmetric.mix_hash(local.public.kem_ek.as_bytes());

        Ok(Self {
            symmetric: Some(symmetric),
            phase: Phase::ResponderReadMessage1,
            is_initiator: false,
            remote_authenticated: false,
            static_kem_seed: local.secret.kem_seed.clone(),
            static_kem_public: *local.public.kem_ek.as_bytes(),
            seec_key: local.secret.seec_key.clone(),
            remote_static_kem_public: None,
            remote_ephemeral_kem_public: None,
            ephemeral_kem_seed: None,
        })
    }

    /// Borrow the live symmetric transcript state or reject a consumed handshake.
    fn symmetric(&mut self) -> Result<&mut SymmetricState, Error> {
        self.symmetric.as_mut().ok_or(Error::WrongState)
    }

    /// Report whether the caller must read, write, or consume the completed state.
    pub fn next_action(&self) -> HandshakeAction {
        match self.phase {
            Phase::InitiatorWriteMessage1
            | Phase::InitiatorWriteMessage3
            | Phase::ResponderWriteMessage2 => HandshakeAction::WriteMessage,
            Phase::InitiatorReadMessage2
            | Phase::ResponderReadMessage1
            | Phase::ResponderReadMessage3 => HandshakeAction::ReadMessage,
            Phase::Complete => HandshakeAction::Complete,
        }
    }

    /// Report whether the next outgoing flight may carry application payload.
    ///
    /// Message 1 always returns `false`; initiator data belongs in Message 3.
    pub fn next_message_accepts_payload(&self) -> bool {
        matches!(
            self.phase,
            Phase::ResponderWriteMessage2 | Phase::InitiatorWriteMessage3
        )
    }

    /// Write the next handshake flight using the operating system RNG.
    pub fn write_message(&mut self, payload: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        self.write_message_with_rng(payload, output, &mut OsRng)
    }

    /// Write the next handshake flight using caller-supplied session coins.
    ///
    /// The coins are hardened with the keypair's persistent SEEC key before use.
    pub fn write_message_with_rng(
        &mut self,
        payload: &[u8],
        output: &mut [u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<usize, Error> {
        match self.phase {
            Phase::InitiatorWriteMessage1 => self.write_message_1(payload, output, rng),
            Phase::ResponderWriteMessage2 => self.write_message_2(payload, output, rng),
            Phase::InitiatorWriteMessage3 => self.write_message_3(payload, output),
            _ => Err(Error::WrongState),
        }
    }

    /// Read and authenticate the next peer flight, returning its payload length.
    pub fn read_message(&mut self, message: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        if message.len() > MAX_MESSAGE_LEN {
            return Err(Error::BadMessage);
        }

        match self.phase {
            Phase::ResponderReadMessage1 => self.read_message_1(message),
            Phase::InitiatorReadMessage2 => self.read_message_2(message, output),
            Phase::ResponderReadMessage3 => self.read_message_3(message, output),
            _ => Err(Error::WrongState),
        }
    }

    /// Return the fixed overhead of the next outgoing flight.
    pub fn next_message_overhead(&self) -> usize {
        match self.phase {
            Phase::InitiatorWriteMessage1 => MSG1_OVERHEAD,
            Phase::ResponderWriteMessage2 => MSG2_OVERHEAD,
            Phase::InitiatorWriteMessage3 => MSG3_OVERHEAD,
            _ => 0,
        }
    }

    /// Return the remote static key only after it has been authenticated.
    pub fn remote_public(&self) -> Option<PqPublicKey> {
        if !self.remote_authenticated {
            return None;
        }

        let remote_static = self.remote_static_kem_public?;

        Some(PqPublicKey {
            kem_ek: EncapsulationKey::from_bytes(remote_static),
        })
    }

    /// Report whether the remote peer has proven possession of its static secret.
    pub fn is_remote_authenticated(&self) -> bool {
        self.remote_authenticated
    }

    /// Borrow the current transcript hash for channel binding or diagnostics.
    pub fn handshake_hash(&self) -> Result<&[u8; HASH_LEN], Error> {
        self.symmetric
            .as_ref()
            .map(SymmetricState::handshake_hash)
            .ok_or(Error::WrongState)
    }

    /// Report whether this state machine is the protocol initiator.
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Derive an Additional Symmetric Key after explicit confirmation completes.
    pub fn get_ask(&self, label: &[u8]) -> Result<[u8; HASH_LEN], Error> {
        if self.phase != Phase::Complete {
            return Err(Error::WrongState);
        }

        let symmetric = self.symmetric.as_ref().ok_or(Error::WrongState)?;
        let (_, _, ask) = hash::hkdf3(symmetric.chaining_key(), label);

        Ok(*ask)
    }

    /// Split a confirmed handshake into bidirectional transport cipher states.
    pub fn into_transport(mut self) -> Result<TransportState, Error> {
        if self.phase != Phase::Complete {
            return Err(Error::WrongState);
        }

        let symmetric = self.symmetric.take().ok_or(Error::WrongState)?;
        let (handshake_hash, initiator_cipher, responder_cipher) = symmetric.split();

        Ok(TransportState::new(
            handshake_hash,
            initiator_cipher,
            responder_cipher,
            self.is_initiator,
        ))
    }

    /// Write `skem_r, ENC(e_kem_i, s_kem_i)` without application payload.
    fn write_message_1(
        &mut self,
        payload: &[u8],
        output: &mut [u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<usize, Error> {
        if !payload.is_empty() {
            return Err(Error::WrongState);
        }

        if output.len() < MSG1_OVERHEAD {
            return Err(Error::BufferTooSmall);
        }

        let remote_static = self.remote_static_kem_public.ok_or(Error::WrongState)?;
        let (static_ciphertext, static_secret) =
            pq::kem_encapsulate(&remote_static, &self.seec_key, PQ_PROTOCOL_NAME, rng)?;

        output[..KEM_CT_LEN].copy_from_slice(&static_ciphertext);
        self.symmetric()?.mix_hash(&static_ciphertext);
        self.symmetric()?.mix_key(static_secret.as_bytes());

        let (ephemeral_seed, ephemeral_public) =
            pq::kem_generate_ephemeral(&self.seec_key, PQ_PROTOCOL_NAME, rng);
        self.ephemeral_kem_seed = Some(ephemeral_seed);

        let mut public_keys = Zeroizing::new([0u8; 2 * KEM_EK_LEN]);
        public_keys[..KEM_EK_LEN].copy_from_slice(&ephemeral_public);
        public_keys[KEM_EK_LEN..].copy_from_slice(&self.static_kem_public);

        let encrypted_length = self
            .symmetric()?
            .encrypt_and_hash(&public_keys[..], &mut output[KEM_CT_LEN..])?;

        if encrypted_length != (2 * KEM_EK_LEN) + AEAD_TAG_LEN {
            return Err(Error::CryptoFailed);
        }

        self.phase = Phase::InitiatorReadMessage2;

        Ok(MSG1_OVERHEAD)
    }

    /// Read Message 1 while retaining the claimed initiator key as pending.
    fn read_message_1(&mut self, message: &[u8]) -> Result<usize, Error> {
        if message.len() != MSG1_OVERHEAD {
            return Err(Error::BadMessage);
        }

        let mut static_ciphertext = [0u8; KEM_CT_LEN];
        static_ciphertext.copy_from_slice(&message[..KEM_CT_LEN]);

        self.symmetric()?.mix_hash(&static_ciphertext);

        let static_secret = pq::kem_decapsulate(&self.static_kem_seed, &static_ciphertext)?;
        self.symmetric()?.mix_key(static_secret.as_bytes());

        let mut public_keys = Zeroizing::new([0u8; 2 * KEM_EK_LEN]);
        let decrypted_length = self
            .symmetric()?
            .decrypt_and_hash(&message[KEM_CT_LEN..], &mut public_keys[..])?;

        if decrypted_length != 2 * KEM_EK_LEN {
            return Err(Error::BadMessage);
        }

        let mut remote_ephemeral = [0u8; KEM_EK_LEN];
        remote_ephemeral.copy_from_slice(&public_keys[..KEM_EK_LEN]);

        let mut remote_static = [0u8; KEM_EK_LEN];
        remote_static.copy_from_slice(&public_keys[KEM_EK_LEN..]);

        self.remote_static_kem_public = Some(remote_static);
        self.remote_ephemeral_kem_public = Some(remote_ephemeral);
        self.phase = Phase::ResponderWriteMessage2;

        Ok(0)
    }

    /// Write `ekem_i, ENC(skem_i), payload_r` and await confirmation.
    fn write_message_2(
        &mut self,
        payload: &[u8],
        output: &mut [u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<usize, Error> {
        let total_length = MSG2_OVERHEAD
            .checked_add(payload.len())
            .ok_or(Error::BadMessage)?;

        if total_length > MAX_MESSAGE_LEN {
            return Err(Error::BadMessage);
        }

        if output.len() < total_length {
            return Err(Error::BufferTooSmall);
        }

        let remote_ephemeral = self.remote_ephemeral_kem_public.ok_or(Error::WrongState)?;
        let (ephemeral_ciphertext, ephemeral_secret) =
            pq::kem_encapsulate(&remote_ephemeral, &self.seec_key, PQ_PROTOCOL_NAME, rng)?;

        output[..KEM_CT_LEN].copy_from_slice(&ephemeral_ciphertext);
        self.symmetric()?.mix_hash(&ephemeral_ciphertext);
        self.symmetric()?.mix_key(ephemeral_secret.as_bytes());

        let remote_static = self.remote_static_kem_public.ok_or(Error::WrongState)?;
        let (static_ciphertext, static_secret) =
            pq::kem_encapsulate(&remote_static, &self.seec_key, PQ_PROTOCOL_NAME, rng)?;

        let encrypted_static_length = self.symmetric()?.encrypt_and_hash(
            &static_ciphertext,
            &mut output[KEM_CT_LEN..KEM_CT_LEN + KEM_CT_LEN + AEAD_TAG_LEN],
        )?;

        if encrypted_static_length != KEM_CT_LEN + AEAD_TAG_LEN {
            return Err(Error::CryptoFailed);
        }

        self.symmetric()?.mix_key(static_secret.as_bytes());

        let payload_offset = KEM_CT_LEN + encrypted_static_length;
        let encrypted_payload_length = self
            .symmetric()?
            .encrypt_and_hash(payload, &mut output[payload_offset..])?;

        self.phase = Phase::ResponderReadMessage3;

        Ok(payload_offset + encrypted_payload_length)
    }

    /// Read Message 2 and authenticate the responder's pinned static key.
    fn read_message_2(&mut self, message: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        if message.len() < MSG2_OVERHEAD {
            return Err(Error::BadMessage);
        }

        let expected_payload_length = message.len() - MSG2_OVERHEAD;

        // Reject before processing tokens so the caller can retry safely.
        if output.len() < expected_payload_length {
            return Err(Error::BufferTooSmall);
        }

        let mut ephemeral_ciphertext = [0u8; KEM_CT_LEN];
        ephemeral_ciphertext.copy_from_slice(&message[..KEM_CT_LEN]);

        self.symmetric()?.mix_hash(&ephemeral_ciphertext);

        let ephemeral_seed = self.ephemeral_kem_seed.as_ref().ok_or(Error::WrongState)?;
        let ephemeral_secret = pq::kem_decapsulate(ephemeral_seed, &ephemeral_ciphertext)?;
        self.symmetric()?.mix_key(ephemeral_secret.as_bytes());

        let encrypted_static_end = KEM_CT_LEN + KEM_CT_LEN + AEAD_TAG_LEN;
        let mut static_ciphertext = Zeroizing::new([0u8; KEM_CT_LEN]);
        let static_ciphertext_length = self.symmetric()?.decrypt_and_hash(
            &message[KEM_CT_LEN..encrypted_static_end],
            &mut static_ciphertext[..],
        )?;

        if static_ciphertext_length != KEM_CT_LEN {
            return Err(Error::BadMessage);
        }

        let static_secret = pq::kem_decapsulate(&self.static_kem_seed, &static_ciphertext)?;
        self.symmetric()?.mix_key(static_secret.as_bytes());

        let decrypted_payload_length = self
            .symmetric()?
            .decrypt_and_hash(&message[encrypted_static_end..], output)?;

        self.remote_authenticated = true;
        self.phase = Phase::InitiatorWriteMessage3;

        Ok(decrypted_payload_length)
    }

    /// Write the explicit confirmation record and the initiator payload.
    fn write_message_3(&mut self, payload: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        let total_length = MSG3_OVERHEAD
            .checked_add(payload.len())
            .ok_or(Error::BadMessage)?;

        if total_length > MAX_MESSAGE_LEN {
            return Err(Error::BadMessage);
        }

        if output.len() < total_length {
            return Err(Error::BufferTooSmall);
        }

        let encrypted_length = self.symmetric()?.encrypt_and_hash(payload, output)?;
        self.phase = Phase::Complete;

        Ok(encrypted_length)
    }

    /// Verify confirmation before exposing the initiator identity or keys.
    fn read_message_3(&mut self, message: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        if message.len() < MSG3_OVERHEAD {
            return Err(Error::BadMessage);
        }

        let payload_length = self.symmetric()?.decrypt_and_hash(message, output)?;

        self.remote_authenticated = true;
        self.phase = Phase::Complete;

        Ok(payload_length)
    }
}
