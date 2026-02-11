//! Hybrid post-quantum Noise IK handshake state machine.
//!
//! Implements `Noise_IKpq_25519+MLKEM768_ChaChaPoly_BLAKE2s`:
//! a hybrid classical + post-quantum IK pattern where every DH token
//! is augmented with a paired ML-KEM-768 KEM operation.
//!
//! ## Pattern
//!
//! ```text
//! IKpq:
//!   <- s_dh, s_kem
//!   ...
//!   -> e_dh, e_kem, es, s, ss
//!   <- e_dh, e_kem, ee, se
//! ```
//!
//! Each combined token (es, ss, ee, se) performs:
//! 1. `mix_key(dh_shared)` — classical protection
//! 2. Write/read KEM ciphertext
//! 3. `mix_hash(kem_ct)` — bind ciphertext to transcript
//! 4. `mix_key(kem_shared)` — post-quantum protection

use rand_core::{CryptoRngCore, OsRng};
use x25519_dalek::PublicKey as DalekPublicKey;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::aead::AEAD_TAG_LEN;
use crate::crypto::hash::{self, HASH_LEN};
use crate::crypto::pq::{self, KEM_CT_LEN, KEM_EK_LEN, KEM_SEED_LEN};
use crate::crypto::x25519::{self, DH_LEN};
use crate::error::Error;
use crate::handshake::HandshakeAction;
use crate::keys::pq::{HYBRID_PUB_LEN, PqKeyPair, PqPublicKey};
use crate::keys::{PublicKey, StaticSecret};
use crate::symmetric_state::SymmetricState;
use crate::transport::TransportState;

/// The Noise protocol name for the hybrid PQ ciphersuite.
pub const PQ_PROTOCOL_NAME: &str = "Noise_IKpq_25519+MLKEM768_ChaChaPoly_BLAKE2s";

/// Message 1 overhead (no payload):
/// e_dh(32) + e_kem(1184) + es_ct(1088) + encrypted_s(1216+16) + ss_ct(1088) + payload_tag(16)
const MSG1_OVERHEAD: usize = DH_LEN                          // 32
    + KEM_EK_LEN                                              // 1184
    + KEM_CT_LEN                                              // 1088
    + HYBRID_PUB_LEN + AEAD_TAG_LEN                          // 1232
    + KEM_CT_LEN                                              // 1088
    + AEAD_TAG_LEN; // 16
// Total: 4640

/// Message 2 overhead (no payload):
/// e_dh(32) + e_kem(1184) + ee_ct(1088) + se_ct(1088) + payload_tag(16)
const MSG2_OVERHEAD: usize = DH_LEN                           // 32
    + KEM_EK_LEN                                              // 1184
    + KEM_CT_LEN                                              // 1088
    + KEM_CT_LEN                                              // 1088
    + AEAD_TAG_LEN; // 16
// Total: 3408

/// Internal state tracking which IK-pq message we're on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    InitiatorWriteMsg1,
    InitiatorReadMsg2,
    ResponderReadMsg1,
    ResponderWriteMsg2,
    Complete,
}

/// A hybrid PQ Noise IK handshake state machine.
///
/// Implements `Noise_IKpq_25519+MLKEM768_ChaChaPoly_BLAKE2s`.
pub struct PqHandshake {
    /// Option so `into_transport()` can `.take()` it.
    symmetric: Option<SymmetricState>,
    phase: Phase,
    is_initiator: bool,

    // --- Standard X25519 DH keys ---
    s_dh: StaticSecret,
    s_dh_pub: [u8; DH_LEN],
    rs_dh: Option<[u8; DH_LEN]>,
    e_dh: Option<StaticSecret>,
    e_dh_pub: Option<[u8; DH_LEN]>,
    re_dh: Option<[u8; DH_LEN]>,

    // --- ML-KEM-768 keys ---
    s_kem_seed: Zeroizing<[u8; KEM_SEED_LEN]>,
    s_kem_ek: [u8; KEM_EK_LEN],
    rs_kem_ek: Option<[u8; KEM_EK_LEN]>,
    e_kem_seed: Option<Zeroizing<[u8; KEM_SEED_LEN]>>,
    e_kem_ek: Option<[u8; KEM_EK_LEN]>,
    re_kem_ek: Option<[u8; KEM_EK_LEN]>,
}

impl Drop for PqHandshake {
    fn drop(&mut self) {
        self.s_dh_pub.zeroize();
        self.s_kem_ek.zeroize();
        if let Some(ref mut v) = self.e_dh_pub {
            v.zeroize();
        }
        if let Some(ref mut v) = self.re_dh {
            v.zeroize();
        }
        if let Some(ref mut v) = self.rs_dh {
            v.zeroize();
        }
        if let Some(ref mut v) = self.rs_kem_ek {
            v.zeroize();
        }
        if let Some(ref mut v) = self.e_kem_ek {
            v.zeroize();
        }
        if let Some(ref mut v) = self.re_kem_ek {
            v.zeroize();
        }
        // s_kem_seed, e_kem_seed: wrapped in Zeroizing, auto-zeroed.
        // s_dh, e_dh: StaticSecret implements ZeroizeOnDrop.
    }
}

impl PqHandshake {
    /// Create a PQ initiator handshake.
    ///
    /// The initiator must know the responder's hybrid public key beforehand.
    pub fn new_initiator(
        local: &PqKeyPair,
        remote_public: &PqPublicKey,
        prologue: &[u8],
    ) -> Result<Self, Error> {
        let mut symmetric = SymmetricState::initialize(PQ_PROTOCOL_NAME);

        symmetric.mix_hash(prologue);

        // IK pre-message: <- s_dh, s_kem
        symmetric.mix_hash(remote_public.dh.as_bytes());
        symmetric.mix_hash(&remote_public.kem_ek);

        Ok(Self {
            symmetric: Some(symmetric),
            phase: Phase::InitiatorWriteMsg1,
            is_initiator: true,
            s_dh: local.secret.dh.clone(),
            s_dh_pub: *local.public.dh.as_bytes(),
            rs_dh: Some(*remote_public.dh.as_bytes()),
            e_dh: None,
            e_dh_pub: None,
            re_dh: None,
            s_kem_seed: local.secret.kem_seed.clone(),
            s_kem_ek: local.public.kem_ek,
            rs_kem_ek: Some(remote_public.kem_ek),
            e_kem_seed: None,
            e_kem_ek: None,
            re_kem_ek: None,
        })
    }

    /// Create a PQ responder handshake.
    pub fn new_responder(local: &PqKeyPair, prologue: &[u8]) -> Result<Self, Error> {
        let mut symmetric = SymmetricState::initialize(PQ_PROTOCOL_NAME);

        symmetric.mix_hash(prologue);

        // IK pre-message: <- s_dh, s_kem (our own keys)
        symmetric.mix_hash(local.public.dh.as_bytes());
        symmetric.mix_hash(&local.public.kem_ek);

        Ok(Self {
            symmetric: Some(symmetric),
            phase: Phase::ResponderReadMsg1,
            is_initiator: false,
            s_dh: local.secret.dh.clone(),
            s_dh_pub: *local.public.dh.as_bytes(),
            rs_dh: None,
            e_dh: None,
            e_dh_pub: None,
            re_dh: None,
            s_kem_seed: local.secret.kem_seed.clone(),
            s_kem_ek: local.public.kem_ek,
            rs_kem_ek: None,
            e_kem_seed: None,
            e_kem_ek: None,
            re_kem_ek: None,
        })
    }

    fn ss(&mut self) -> Result<&mut SymmetricState, Error> {
        self.symmetric.as_mut().ok_or(Error::WrongState)
    }

    /// What action the caller should take next.
    pub fn next_action(&self) -> HandshakeAction {
        match self.phase {
            Phase::InitiatorWriteMsg1 | Phase::ResponderWriteMsg2 => HandshakeAction::WriteMessage,
            Phase::InitiatorReadMsg2 | Phase::ResponderReadMsg1 => HandshakeAction::ReadMessage,
            Phase::Complete => HandshakeAction::Complete,
        }
    }

    /// Write the next handshake message.
    pub fn write_message(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        self.write_message_with_rng(payload, out, &mut OsRng)
    }

    /// Write the next handshake message with a specific RNG.
    pub fn write_message_with_rng(
        &mut self,
        payload: &[u8],
        out: &mut [u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<usize, Error> {
        match self.phase {
            Phase::InitiatorWriteMsg1 => self.write_msg1(payload, out, rng),
            Phase::ResponderWriteMsg2 => self.write_msg2(payload, out, rng),
            _ => Err(Error::WrongState),
        }
    }

    /// Read a handshake message from the peer.
    pub fn read_message(&mut self, message: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        match self.phase {
            Phase::ResponderReadMsg1 => self.read_msg1(message, out),
            Phase::InitiatorReadMsg2 => self.read_msg2(message, out),
            _ => Err(Error::WrongState),
        }
    }

    /// The overhead (in bytes) of the next message beyond the payload.
    pub fn next_message_overhead(&self) -> usize {
        match self.phase {
            Phase::InitiatorWriteMsg1 => MSG1_OVERHEAD,
            Phase::ResponderWriteMsg2 => MSG2_OVERHEAD,
            _ => 0,
        }
    }

    /// The remote peer's hybrid public key, if known.
    pub fn remote_public(&self) -> Option<PqPublicKey> {
        let dh = self.rs_dh?;
        let kem_ek = self.rs_kem_ek?;
        Some(PqPublicKey {
            dh: PublicKey::from_bytes(dh),
            kem_ek,
        })
    }

    /// The remote peer's X25519 public key bytes, if known.
    pub fn remote_dh_public_bytes(&self) -> Option<[u8; DH_LEN]> {
        self.rs_dh
    }

    /// The current handshake hash.
    pub fn handshake_hash(&self) -> Result<&[u8; HASH_LEN], Error> {
        self.symmetric
            .as_ref()
            .map(|s| s.handshake_hash())
            .ok_or(Error::WrongState)
    }

    /// Whether this side is the initiator.
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Derive an Additional Symmetric Key (ASK) from the handshake.
    pub fn get_ask(&self, label: &[u8]) -> Result<[u8; HASH_LEN], Error> {
        if self.phase != Phase::Complete {
            return Err(Error::WrongState);
        }
        let ss = self.symmetric.as_ref().ok_or(Error::WrongState)?;
        let (_, _, ask) = hash::hkdf3(ss.chaining_key(), label);
        Ok(*ask)
    }

    /// Convert the completed handshake into transport state.
    pub fn into_transport(mut self) -> Result<TransportState, Error> {
        if self.phase != Phase::Complete {
            return Err(Error::WrongState);
        }
        let is_initiator = self.is_initiator;
        let symmetric = self.symmetric.take().ok_or(Error::WrongState)?;
        let (h, c1, c2) = symmetric.split();
        Ok(TransportState::new(h, c1, c2, is_initiator))
    }

    // ===== Message 1: initiator writes -> e_dh, e_kem, es, s, ss =====
    //
    // Layout: [e_dh_pub(32)][e_kem_ek(1184)][es_kem_ct(1088)]
    //         [encrypted_s(1216+16)][ss_kem_ct(1088)][encrypted_payload(N+16)]

    fn write_msg1(
        &mut self,
        payload: &[u8],
        out: &mut [u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<usize, Error> {
        let total = MSG1_OVERHEAD
            .checked_add(payload.len())
            .ok_or(Error::BufferTooSmall)?;
        if out.len() < total {
            return Err(Error::BufferTooSmall);
        }

        let mut offset = 0;

        // -> e_dh: generate ephemeral X25519
        let (e_dh_secret, e_dh_pub) = x25519::generate_keypair(rng);
        out[offset..offset + DH_LEN].copy_from_slice(&e_dh_pub);
        self.ss()?.mix_hash(&e_dh_pub);
        self.e_dh = Some(StaticSecret::from_dalek(e_dh_secret));
        self.e_dh_pub = Some(e_dh_pub);
        offset += DH_LEN;

        // -> e_kem: generate ephemeral ML-KEM-768
        let (e_kem_seed, e_kem_ek) = pq::kem_generate(rng);
        out[offset..offset + KEM_EK_LEN].copy_from_slice(&e_kem_ek);
        self.ss()?.mix_hash(&e_kem_ek);
        self.e_kem_seed = Some(e_kem_seed);
        self.e_kem_ek = Some(e_kem_ek);
        offset += KEM_EK_LEN;

        // -> es: DH(e_dh, rs_dh) then KEM_ENCAPS(rs_kem)
        let rs_dh = self.rs_dh.ok_or(Error::WrongState)?;
        let rs_kem_ek = self.rs_kem_ek.ok_or(Error::WrongState)?;

        //   1. Classical DH
        let dh_es = x25519::dh(
            self.e_dh.as_ref().ok_or(Error::WrongState)?.inner(),
            &DalekPublicKey::from(rs_dh),
        )?;
        self.ss()?.mix_key(dh_es.as_bytes());

        //   2. KEM encapsulation + write ct + mix_hash + mix_key
        let (es_ct, es_kem_ss) = pq::kem_encapsulate(&rs_kem_ek, rng)?;
        out[offset..offset + KEM_CT_LEN].copy_from_slice(&es_ct);
        self.ss()?.mix_hash(&es_ct);
        self.ss()?.mix_key(es_kem_ss.as_bytes());
        offset += KEM_CT_LEN;

        // -> s: encrypt_and_hash(s_dh_pub || s_kem_ek)
        let mut s_hybrid = [0u8; HYBRID_PUB_LEN];
        s_hybrid[..DH_LEN].copy_from_slice(&self.s_dh_pub);
        s_hybrid[DH_LEN..].copy_from_slice(&self.s_kem_ek);
        let s_len = self.ss()?.encrypt_and_hash(&s_hybrid, &mut out[offset..])?;
        s_hybrid.zeroize();
        offset += s_len;

        // -> ss: DH(s_dh, rs_dh) then KEM_ENCAPS(rs_kem)
        let dh_ss = x25519::dh(self.s_dh.inner(), &DalekPublicKey::from(rs_dh))?;
        self.ss()?.mix_key(dh_ss.as_bytes());

        let (ss_ct, ss_kem_ss) = pq::kem_encapsulate(&rs_kem_ek, rng)?;
        out[offset..offset + KEM_CT_LEN].copy_from_slice(&ss_ct);
        self.ss()?.mix_hash(&ss_ct);
        self.ss()?.mix_key(ss_kem_ss.as_bytes());
        offset += KEM_CT_LEN;

        // Encrypt payload
        let p_len = self.ss()?.encrypt_and_hash(payload, &mut out[offset..])?;
        offset += p_len;

        self.phase = Phase::InitiatorReadMsg2;
        Ok(offset)
    }

    // ===== Message 1: responder reads -> e_dh, e_kem, es, s, ss =====

    fn read_msg1(&mut self, message: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if message.len() < MSG1_OVERHEAD {
            return Err(Error::BadMessage);
        }

        let mut offset = 0;

        // -> e_dh
        let mut re_dh = [0u8; DH_LEN];
        re_dh.copy_from_slice(&message[offset..offset + DH_LEN]);
        self.ss()?.mix_hash(&re_dh);
        self.re_dh = Some(re_dh);
        offset += DH_LEN;

        // -> e_kem
        let mut re_kem_ek = [0u8; KEM_EK_LEN];
        re_kem_ek.copy_from_slice(&message[offset..offset + KEM_EK_LEN]);
        self.ss()?.mix_hash(&re_kem_ek);
        self.re_kem_ek = Some(re_kem_ek);
        offset += KEM_EK_LEN;

        // -> es: DH(s_dh, re_dh) then KEM_DECAPS(s_kem, es_ct)
        let dh_es = x25519::dh(self.s_dh.inner(), &DalekPublicKey::from(re_dh))?;
        self.ss()?.mix_key(dh_es.as_bytes());

        let mut es_ct = [0u8; KEM_CT_LEN];
        es_ct.copy_from_slice(&message[offset..offset + KEM_CT_LEN]);
        self.ss()?.mix_hash(&es_ct);
        let es_kem_ss = pq::kem_decapsulate(&self.s_kem_seed, &es_ct)?;
        self.ss()?.mix_key(es_kem_ss.as_bytes());
        offset += KEM_CT_LEN;

        // -> s: decrypt_and_hash → recover s_dh_pub || s_kem_ek
        let encrypted_s_len = HYBRID_PUB_LEN + AEAD_TAG_LEN;
        let mut s_hybrid = [0u8; HYBRID_PUB_LEN];
        let s_len = self
            .ss()?
            .decrypt_and_hash(&message[offset..offset + encrypted_s_len], &mut s_hybrid)?;
        if s_len != HYBRID_PUB_LEN {
            s_hybrid.zeroize();
            return Err(Error::BadMessage);
        }

        let mut rs_dh = [0u8; DH_LEN];
        rs_dh.copy_from_slice(&s_hybrid[..DH_LEN]);
        let mut rs_kem_ek = [0u8; KEM_EK_LEN];
        rs_kem_ek.copy_from_slice(&s_hybrid[DH_LEN..]);
        self.rs_dh = Some(rs_dh);
        self.rs_kem_ek = Some(rs_kem_ek);
        s_hybrid.zeroize();
        offset += encrypted_s_len;

        // -> ss: DH(s_dh, rs_dh) then KEM_DECAPS(s_kem, ss_ct)
        let dh_ss = x25519::dh(self.s_dh.inner(), &DalekPublicKey::from(rs_dh))?;
        self.ss()?.mix_key(dh_ss.as_bytes());

        let mut ss_ct = [0u8; KEM_CT_LEN];
        ss_ct.copy_from_slice(&message[offset..offset + KEM_CT_LEN]);
        self.ss()?.mix_hash(&ss_ct);
        let ss_kem_ss = pq::kem_decapsulate(&self.s_kem_seed, &ss_ct)?;
        self.ss()?.mix_key(ss_kem_ss.as_bytes());
        offset += KEM_CT_LEN;

        // Decrypt payload
        let remaining = &message[offset..];
        if remaining.len() < AEAD_TAG_LEN {
            return Err(Error::BadMessage);
        }
        let p_len = self.ss()?.decrypt_and_hash(remaining, out)?;

        self.phase = Phase::ResponderWriteMsg2;
        Ok(p_len)
    }

    // ===== Message 2: responder writes <- e_dh, e_kem, ee, se =====
    //
    // Layout: [e_dh_pub(32)][e_kem_ek(1184)][ee_kem_ct(1088)]
    //         [se_kem_ct(1088)][encrypted_payload(N+16)]

    fn write_msg2(
        &mut self,
        payload: &[u8],
        out: &mut [u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<usize, Error> {
        let total = MSG2_OVERHEAD
            .checked_add(payload.len())
            .ok_or(Error::BufferTooSmall)?;
        if out.len() < total {
            return Err(Error::BufferTooSmall);
        }

        let mut offset = 0;

        // <- e_dh: generate ephemeral X25519
        let (e_dh_secret, e_dh_pub) = x25519::generate_keypair(rng);
        out[offset..offset + DH_LEN].copy_from_slice(&e_dh_pub);
        self.ss()?.mix_hash(&e_dh_pub);
        self.e_dh = Some(StaticSecret::from_dalek(e_dh_secret));
        self.e_dh_pub = Some(e_dh_pub);
        offset += DH_LEN;

        // <- e_kem: generate ephemeral ML-KEM-768
        let (e_kem_seed, e_kem_ek) = pq::kem_generate(rng);
        out[offset..offset + KEM_EK_LEN].copy_from_slice(&e_kem_ek);
        self.ss()?.mix_hash(&e_kem_ek);
        self.e_kem_seed = Some(e_kem_seed);
        self.e_kem_ek = Some(e_kem_ek);
        offset += KEM_EK_LEN;

        // <- ee: DH(e_dh, re_dh) then KEM_ENCAPS(re_kem)
        let re_dh = self.re_dh.ok_or(Error::WrongState)?;
        let re_kem_ek = self.re_kem_ek.ok_or(Error::WrongState)?;

        let dh_ee = x25519::dh(
            self.e_dh.as_ref().ok_or(Error::WrongState)?.inner(),
            &DalekPublicKey::from(re_dh),
        )?;
        self.ss()?.mix_key(dh_ee.as_bytes());

        let (ee_ct, ee_kem_ss) = pq::kem_encapsulate(&re_kem_ek, rng)?;
        out[offset..offset + KEM_CT_LEN].copy_from_slice(&ee_ct);
        self.ss()?.mix_hash(&ee_ct);
        self.ss()?.mix_key(ee_kem_ss.as_bytes());
        offset += KEM_CT_LEN;

        // <- se: DH(e_dh, rs_dh) then KEM_ENCAPS(rs_kem)
        let rs_dh = self.rs_dh.ok_or(Error::WrongState)?;
        let rs_kem_ek = self.rs_kem_ek.ok_or(Error::WrongState)?;

        let dh_se = x25519::dh(
            self.e_dh.as_ref().ok_or(Error::WrongState)?.inner(),
            &DalekPublicKey::from(rs_dh),
        )?;
        self.ss()?.mix_key(dh_se.as_bytes());

        let (se_ct, se_kem_ss) = pq::kem_encapsulate(&rs_kem_ek, rng)?;
        out[offset..offset + KEM_CT_LEN].copy_from_slice(&se_ct);
        self.ss()?.mix_hash(&se_ct);
        self.ss()?.mix_key(se_kem_ss.as_bytes());
        offset += KEM_CT_LEN;

        // Encrypt payload
        let p_len = self.ss()?.encrypt_and_hash(payload, &mut out[offset..])?;
        offset += p_len;

        self.phase = Phase::Complete;
        Ok(offset)
    }

    // ===== Message 2: initiator reads <- e_dh, e_kem, ee, se =====

    fn read_msg2(&mut self, message: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if message.len() < MSG2_OVERHEAD {
            return Err(Error::BadMessage);
        }

        let mut offset = 0;

        // <- e_dh
        let mut re_dh = [0u8; DH_LEN];
        re_dh.copy_from_slice(&message[offset..offset + DH_LEN]);
        self.ss()?.mix_hash(&re_dh);
        self.re_dh = Some(re_dh);
        offset += DH_LEN;

        // <- e_kem
        let mut re_kem_ek = [0u8; KEM_EK_LEN];
        re_kem_ek.copy_from_slice(&message[offset..offset + KEM_EK_LEN]);
        self.ss()?.mix_hash(&re_kem_ek);
        self.re_kem_ek = Some(re_kem_ek);
        offset += KEM_EK_LEN;

        // <- ee: DH(e_dh, re_dh) then KEM_DECAPS(e_kem, ee_ct)
        let dh_ee = x25519::dh(
            self.e_dh.as_ref().ok_or(Error::WrongState)?.inner(),
            &DalekPublicKey::from(re_dh),
        )?;
        self.ss()?.mix_key(dh_ee.as_bytes());

        let mut ee_ct = [0u8; KEM_CT_LEN];
        ee_ct.copy_from_slice(&message[offset..offset + KEM_CT_LEN]);
        self.ss()?.mix_hash(&ee_ct);
        let e_kem_seed = self.e_kem_seed.as_ref().ok_or(Error::WrongState)?;
        let ee_kem_ss = pq::kem_decapsulate(e_kem_seed, &ee_ct)?;
        self.ss()?.mix_key(ee_kem_ss.as_bytes());
        offset += KEM_CT_LEN;

        // <- se: DH(s_dh, re_dh) then KEM_DECAPS(s_kem, se_ct)
        let dh_se = x25519::dh(self.s_dh.inner(), &DalekPublicKey::from(re_dh))?;
        self.ss()?.mix_key(dh_se.as_bytes());

        let mut se_ct = [0u8; KEM_CT_LEN];
        se_ct.copy_from_slice(&message[offset..offset + KEM_CT_LEN]);
        self.ss()?.mix_hash(&se_ct);
        let se_kem_ss = pq::kem_decapsulate(&self.s_kem_seed, &se_ct)?;
        self.ss()?.mix_key(se_kem_ss.as_bytes());
        offset += KEM_CT_LEN;

        // Decrypt payload
        let remaining = &message[offset..];
        if remaining.len() < AEAD_TAG_LEN {
            return Err(Error::BadMessage);
        }
        let p_len = self.ss()?.decrypt_and_hash(remaining, out)?;

        self.phase = Phase::Complete;
        Ok(p_len)
    }
}
