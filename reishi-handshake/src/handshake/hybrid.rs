//! Confirmed hybrid classical IK + `pqIK` handshake.
//!
//! ```text
//! <- s_dh, s_kem
//! ...
//! -> skem_r, e_dh_i, es, ENC(e_kem_i, s_dh_i, s_kem_i), ss
//! <- ekem_i, ENC(skem_i), e_dh_r, ee, se, payload_r
//! -> ENC(confirm, payload_i)
//! ```

use rand_core::{CryptoRngCore, OsRng};
use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret as DalekStaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::aead::AEAD_TAG_LEN;
use crate::crypto::hash::{self, HASH_LEN};
use crate::crypto::pq::{self, KEM_CT_LEN, KEM_EK_LEN, KEM_SEED_LEN};
use crate::crypto::x25519::{self, DH_LEN};
use crate::error::Error;
use crate::handshake::standard::HandshakeAction;
use crate::keys::pq::{EncapsulationKey, HybridKeyPair, HybridPublicKey};
use crate::keys::{PublicKey, StaticSecret};
use crate::symmetric_state::SymmetricState;
use crate::transport::TransportState;

/// Transcript name for the fixed confirmed hybrid ciphersuite.
pub const HYBRID_PROTOCOL_NAME: &str = "Noise_hybridIKkc_25519+MLKEM768_ChaChaPoly_BLAKE2s";
/// Largest handshake message accepted or emitted by the state machine.
pub const MAX_MESSAGE_LEN: usize = 65535;

const ENCRYPTED_INITIATOR_KEYS_LEN: usize = KEM_EK_LEN + DH_LEN + KEM_EK_LEN + AEAD_TAG_LEN;

/// Fixed Message 1 overhead; application payload is forbidden in this flight.
pub const MSG1_OVERHEAD: usize = KEM_CT_LEN + DH_LEN + ENCRYPTED_INITIATOR_KEYS_LEN;
/// Fixed Message 2 overhead before the responder payload.
pub const MSG2_OVERHEAD: usize = KEM_CT_LEN + KEM_CT_LEN + AEAD_TAG_LEN + DH_LEN + AEAD_TAG_LEN;
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

/// State machine for confirmed hybrid classical IK + `pqIK`.
///
/// Both DH and KEM secrets enter the chaining key in wire-pattern order. The
/// responder withholds the claimed initiator identity until Message 3 verifies.
pub struct HybridHandshake {
    symmetric: Option<SymmetricState>,
    phase: Phase,
    is_initiator: bool,
    remote_authenticated: bool,

    static_dh: StaticSecret,
    static_dh_public: [u8; DH_LEN],
    remote_static_dh_public: Option<[u8; DH_LEN]>,
    ephemeral_dh: Option<StaticSecret>,
    remote_ephemeral_dh_public: Option<[u8; DH_LEN]>,

    static_kem_seed: Zeroizing<[u8; KEM_SEED_LEN]>,
    static_kem_public: [u8; KEM_EK_LEN],
    seec_key: Zeroizing<[u8; 32]>,
    remote_static_kem_public: Option<[u8; KEM_EK_LEN]>,
    ephemeral_kem_seed: Option<Zeroizing<[u8; KEM_SEED_LEN]>>,
    remote_ephemeral_kem_public: Option<[u8; KEM_EK_LEN]>,
}

impl Drop for HybridHandshake {
    fn drop(&mut self) {
        self.static_dh_public.zeroize();
        self.static_kem_public.zeroize();

        if let Some(remote_static_dh) = &mut self.remote_static_dh_public {
            remote_static_dh.zeroize();
        }

        if let Some(remote_ephemeral_dh) = &mut self.remote_ephemeral_dh_public {
            remote_ephemeral_dh.zeroize();
        }

        if let Some(remote_static_kem) = &mut self.remote_static_kem_public {
            remote_static_kem.zeroize();
        }

        if let Some(remote_ephemeral_kem) = &mut self.remote_ephemeral_kem_public {
            remote_ephemeral_kem.zeroize();
        }
    }
}

impl HybridHandshake {
    /// Start an initiator handshake with the responder's pinned hybrid key.
    pub fn new_initiator(
        local: &HybridKeyPair,
        remote_public: &HybridPublicKey,
        prologue: &[u8],
    ) -> Result<Self, Error> {
        let mut symmetric = SymmetricState::initialize(HYBRID_PROTOCOL_NAME);
        symmetric.mix_hash(prologue);
        symmetric.mix_hash(remote_public.dh.as_bytes());
        symmetric.mix_hash(remote_public.kem_ek.as_bytes());

        Ok(Self {
            symmetric: Some(symmetric),
            phase: Phase::InitiatorWriteMessage1,
            is_initiator: true,
            remote_authenticated: false,
            static_dh: local.secret.dh.clone(),
            static_dh_public: *local.public.dh.as_bytes(),
            remote_static_dh_public: Some(*remote_public.dh.as_bytes()),
            ephemeral_dh: None,
            remote_ephemeral_dh_public: None,
            static_kem_seed: local.secret.kem_seed.clone(),
            static_kem_public: *local.public.kem_ek.as_bytes(),
            seec_key: local.secret.seec_key.clone(),
            remote_static_kem_public: Some(*remote_public.kem_ek.as_bytes()),
            ephemeral_kem_seed: None,
            remote_ephemeral_kem_public: None,
        })
    }

    /// Start a responder handshake without assuming an initiator identity.
    pub fn new_responder(local: &HybridKeyPair, prologue: &[u8]) -> Result<Self, Error> {
        let mut symmetric = SymmetricState::initialize(HYBRID_PROTOCOL_NAME);
        symmetric.mix_hash(prologue);
        symmetric.mix_hash(local.public.dh.as_bytes());
        symmetric.mix_hash(local.public.kem_ek.as_bytes());

        Ok(Self {
            symmetric: Some(symmetric),
            phase: Phase::ResponderReadMessage1,
            is_initiator: false,
            remote_authenticated: false,
            static_dh: local.secret.dh.clone(),
            static_dh_public: *local.public.dh.as_bytes(),
            remote_static_dh_public: None,
            ephemeral_dh: None,
            remote_ephemeral_dh_public: None,
            static_kem_seed: local.secret.kem_seed.clone(),
            static_kem_public: *local.public.kem_ek.as_bytes(),
            seec_key: local.secret.seec_key.clone(),
            remote_static_kem_public: None,
            ephemeral_kem_seed: None,
            remote_ephemeral_kem_public: None,
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
    /// ML-KEM coins and X25519 ephemeral secrets are hardened with the
    /// keypair's persistent SEEC key.
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

    /// Return the remote hybrid static key only after authentication.
    pub fn remote_public(&self) -> Option<HybridPublicKey> {
        if !self.remote_authenticated {
            return None;
        }

        let remote_dh = self.remote_static_dh_public?;
        let remote_kem = self.remote_static_kem_public?;

        Some(HybridPublicKey {
            dh: PublicKey::from_bytes(remote_dh),
            kem_ek: EncapsulationKey::from_bytes(remote_kem),
        })
    }

    /// Return the authenticated remote X25519 component for typed integrations.
    pub fn remote_dh_public_bytes(&self) -> Option<[u8; DH_LEN]> {
        self.remote_public().map(|public| *public.dh.as_bytes())
    }

    /// Report whether the remote peer has proven possession of its static secrets.
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

    /// Write the hybrid Message 1 tokens without application payload.
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

        let remote_static_kem = self.remote_static_kem_public.ok_or(Error::WrongState)?;
        let (static_kem_ciphertext, static_kem_secret) = pq::kem_encapsulate(
            &remote_static_kem,
            &self.seec_key,
            HYBRID_PROTOCOL_NAME,
            rng,
        )?;

        output[..KEM_CT_LEN].copy_from_slice(&static_kem_ciphertext);
        self.symmetric()?.mix_hash(&static_kem_ciphertext);
        self.symmetric()?.mix_key(static_kem_secret.as_bytes());

        let dh_offset = KEM_CT_LEN;
        let ephemeral_dh_bytes =
            pq::seec_ephemeral_dh_secret(&self.seec_key, HYBRID_PROTOCOL_NAME, rng);
        let ephemeral_dh = DalekStaticSecret::from(*ephemeral_dh_bytes);
        let ephemeral_dh_public = DalekPublicKey::from(&ephemeral_dh).to_bytes();

        output[dh_offset..dh_offset + DH_LEN].copy_from_slice(&ephemeral_dh_public);
        self.symmetric()?.mix_hash(&ephemeral_dh_public);
        self.ephemeral_dh = Some(StaticSecret::from_dalek(ephemeral_dh));

        let remote_static_dh = self.remote_static_dh_public.ok_or(Error::WrongState)?;
        let es_secret = x25519::dh(
            self.ephemeral_dh.as_ref().ok_or(Error::WrongState)?.inner(),
            &DalekPublicKey::from(remote_static_dh),
        )?;
        self.symmetric()?.mix_key(es_secret.as_bytes());

        let (ephemeral_kem_seed, ephemeral_kem_public) =
            pq::kem_generate_ephemeral(&self.seec_key, HYBRID_PROTOCOL_NAME, rng);
        self.ephemeral_kem_seed = Some(ephemeral_kem_seed);

        let mut initiator_keys = Zeroizing::new([0u8; KEM_EK_LEN + DH_LEN + KEM_EK_LEN]);
        initiator_keys[..KEM_EK_LEN].copy_from_slice(&ephemeral_kem_public);
        initiator_keys[KEM_EK_LEN..KEM_EK_LEN + DH_LEN].copy_from_slice(&self.static_dh_public);
        initiator_keys[KEM_EK_LEN + DH_LEN..].copy_from_slice(&self.static_kem_public);

        let encrypted_keys_offset = dh_offset + DH_LEN;
        let encrypted_keys_length = self
            .symmetric()?
            .encrypt_and_hash(&initiator_keys[..], &mut output[encrypted_keys_offset..])?;

        if encrypted_keys_length != ENCRYPTED_INITIATOR_KEYS_LEN {
            return Err(Error::CryptoFailed);
        }

        let ss_secret = x25519::dh(
            self.static_dh.inner(),
            &DalekPublicKey::from(remote_static_dh),
        )?;
        self.symmetric()?.mix_key(ss_secret.as_bytes());

        self.phase = Phase::InitiatorReadMessage2;

        Ok(MSG1_OVERHEAD)
    }

    /// Read Message 1 while retaining the claimed initiator key as pending.
    fn read_message_1(&mut self, message: &[u8]) -> Result<usize, Error> {
        if message.len() != MSG1_OVERHEAD {
            return Err(Error::BadMessage);
        }

        let mut static_kem_ciphertext = [0u8; KEM_CT_LEN];
        static_kem_ciphertext.copy_from_slice(&message[..KEM_CT_LEN]);

        self.symmetric()?.mix_hash(&static_kem_ciphertext);

        let static_kem_secret = pq::kem_decapsulate(&self.static_kem_seed, &static_kem_ciphertext)?;
        self.symmetric()?.mix_key(static_kem_secret.as_bytes());

        let dh_offset = KEM_CT_LEN;
        let mut remote_ephemeral_dh = [0u8; DH_LEN];
        remote_ephemeral_dh.copy_from_slice(&message[dh_offset..dh_offset + DH_LEN]);

        self.symmetric()?.mix_hash(&remote_ephemeral_dh);
        self.remote_ephemeral_dh_public = Some(remote_ephemeral_dh);

        let es_secret = x25519::dh(
            self.static_dh.inner(),
            &DalekPublicKey::from(remote_ephemeral_dh),
        )?;
        self.symmetric()?.mix_key(es_secret.as_bytes());

        let encrypted_keys_offset = dh_offset + DH_LEN;
        let mut initiator_keys = Zeroizing::new([0u8; KEM_EK_LEN + DH_LEN + KEM_EK_LEN]);
        let decrypted_keys_length = self
            .symmetric()?
            .decrypt_and_hash(&message[encrypted_keys_offset..], &mut initiator_keys[..])?;

        if decrypted_keys_length != KEM_EK_LEN + DH_LEN + KEM_EK_LEN {
            return Err(Error::BadMessage);
        }

        let mut remote_ephemeral_kem = [0u8; KEM_EK_LEN];
        remote_ephemeral_kem.copy_from_slice(&initiator_keys[..KEM_EK_LEN]);

        let mut remote_static_dh = [0u8; DH_LEN];
        remote_static_dh.copy_from_slice(&initiator_keys[KEM_EK_LEN..KEM_EK_LEN + DH_LEN]);

        let mut remote_static_kem = [0u8; KEM_EK_LEN];
        remote_static_kem.copy_from_slice(&initiator_keys[KEM_EK_LEN + DH_LEN..]);

        self.remote_ephemeral_kem_public = Some(remote_ephemeral_kem);
        self.remote_static_dh_public = Some(remote_static_dh);
        self.remote_static_kem_public = Some(remote_static_kem);

        let ss_secret = x25519::dh(
            self.static_dh.inner(),
            &DalekPublicKey::from(remote_static_dh),
        )?;
        self.symmetric()?.mix_key(ss_secret.as_bytes());

        self.phase = Phase::ResponderWriteMessage2;

        Ok(0)
    }

    /// Write the hybrid Message 2 tokens and responder payload.
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

        let remote_ephemeral_kem = self.remote_ephemeral_kem_public.ok_or(Error::WrongState)?;
        let (ephemeral_kem_ciphertext, ephemeral_kem_secret) = pq::kem_encapsulate(
            &remote_ephemeral_kem,
            &self.seec_key,
            HYBRID_PROTOCOL_NAME,
            rng,
        )?;

        output[..KEM_CT_LEN].copy_from_slice(&ephemeral_kem_ciphertext);
        self.symmetric()?.mix_hash(&ephemeral_kem_ciphertext);
        self.symmetric()?.mix_key(ephemeral_kem_secret.as_bytes());

        let remote_static_kem = self.remote_static_kem_public.ok_or(Error::WrongState)?;
        let (static_kem_ciphertext, static_kem_secret) = pq::kem_encapsulate(
            &remote_static_kem,
            &self.seec_key,
            HYBRID_PROTOCOL_NAME,
            rng,
        )?;

        let encrypted_static_end = KEM_CT_LEN + KEM_CT_LEN + AEAD_TAG_LEN;
        let encrypted_static_length = self.symmetric()?.encrypt_and_hash(
            &static_kem_ciphertext,
            &mut output[KEM_CT_LEN..encrypted_static_end],
        )?;

        if encrypted_static_length != KEM_CT_LEN + AEAD_TAG_LEN {
            return Err(Error::CryptoFailed);
        }

        self.symmetric()?.mix_key(static_kem_secret.as_bytes());

        let ephemeral_dh_bytes =
            pq::seec_ephemeral_dh_secret(&self.seec_key, HYBRID_PROTOCOL_NAME, rng);
        let ephemeral_dh = DalekStaticSecret::from(*ephemeral_dh_bytes);
        let ephemeral_dh_public = DalekPublicKey::from(&ephemeral_dh).to_bytes();

        output[encrypted_static_end..encrypted_static_end + DH_LEN]
            .copy_from_slice(&ephemeral_dh_public);
        self.symmetric()?.mix_hash(&ephemeral_dh_public);
        self.ephemeral_dh = Some(StaticSecret::from_dalek(ephemeral_dh));

        let remote_ephemeral_dh = self.remote_ephemeral_dh_public.ok_or(Error::WrongState)?;
        let ee_secret = x25519::dh(
            self.ephemeral_dh.as_ref().ok_or(Error::WrongState)?.inner(),
            &DalekPublicKey::from(remote_ephemeral_dh),
        )?;
        self.symmetric()?.mix_key(ee_secret.as_bytes());

        let remote_static_dh = self.remote_static_dh_public.ok_or(Error::WrongState)?;
        let se_secret = x25519::dh(
            self.ephemeral_dh.as_ref().ok_or(Error::WrongState)?.inner(),
            &DalekPublicKey::from(remote_static_dh),
        )?;
        self.symmetric()?.mix_key(se_secret.as_bytes());

        let payload_offset = encrypted_static_end + DH_LEN;
        let encrypted_payload_length = self
            .symmetric()?
            .encrypt_and_hash(payload, &mut output[payload_offset..])?;

        self.phase = Phase::ResponderReadMessage3;

        Ok(payload_offset + encrypted_payload_length)
    }

    /// Read Message 2 and authenticate the responder's pinned hybrid key.
    fn read_message_2(&mut self, message: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        if message.len() < MSG2_OVERHEAD {
            return Err(Error::BadMessage);
        }

        let expected_payload_length = message.len() - MSG2_OVERHEAD;

        // Reject before processing tokens so the caller can retry safely.
        if output.len() < expected_payload_length {
            return Err(Error::BufferTooSmall);
        }

        let mut ephemeral_kem_ciphertext = [0u8; KEM_CT_LEN];
        ephemeral_kem_ciphertext.copy_from_slice(&message[..KEM_CT_LEN]);

        self.symmetric()?.mix_hash(&ephemeral_kem_ciphertext);

        let ephemeral_kem_seed = self.ephemeral_kem_seed.as_ref().ok_or(Error::WrongState)?;
        let ephemeral_kem_secret =
            pq::kem_decapsulate(ephemeral_kem_seed, &ephemeral_kem_ciphertext)?;
        self.symmetric()?.mix_key(ephemeral_kem_secret.as_bytes());

        let encrypted_static_end = KEM_CT_LEN + KEM_CT_LEN + AEAD_TAG_LEN;
        let mut static_kem_ciphertext = Zeroizing::new([0u8; KEM_CT_LEN]);
        let static_kem_ciphertext_length = self.symmetric()?.decrypt_and_hash(
            &message[KEM_CT_LEN..encrypted_static_end],
            &mut static_kem_ciphertext[..],
        )?;

        if static_kem_ciphertext_length != KEM_CT_LEN {
            return Err(Error::BadMessage);
        }

        let static_kem_secret = pq::kem_decapsulate(&self.static_kem_seed, &static_kem_ciphertext)?;
        self.symmetric()?.mix_key(static_kem_secret.as_bytes());

        let mut remote_ephemeral_dh = [0u8; DH_LEN];
        remote_ephemeral_dh
            .copy_from_slice(&message[encrypted_static_end..encrypted_static_end + DH_LEN]);

        self.symmetric()?.mix_hash(&remote_ephemeral_dh);
        self.remote_ephemeral_dh_public = Some(remote_ephemeral_dh);

        let ee_secret = x25519::dh(
            self.ephemeral_dh.as_ref().ok_or(Error::WrongState)?.inner(),
            &DalekPublicKey::from(remote_ephemeral_dh),
        )?;
        self.symmetric()?.mix_key(ee_secret.as_bytes());

        let se_secret = x25519::dh(
            self.static_dh.inner(),
            &DalekPublicKey::from(remote_ephemeral_dh),
        )?;
        self.symmetric()?.mix_key(se_secret.as_bytes());

        let payload_offset = encrypted_static_end + DH_LEN;
        let decrypted_payload_length = self
            .symmetric()?
            .decrypt_and_hash(&message[payload_offset..], output)?;

        self.remote_authenticated = true;
        self.phase = Phase::InitiatorWriteMessage3;

        Ok(decrypted_payload_length)
    }

    /// Write the explicit confirmation record and initiator payload.
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
