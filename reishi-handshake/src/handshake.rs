use rand_core::{CryptoRngCore, OsRng};
use x25519_dalek::PublicKey as DalekPublicKey;
use zeroize::Zeroize;

use crate::crypto::aead::AEAD_TAG_LEN;
use crate::crypto::hash::{self, HASH_LEN};
use crate::crypto::x25519::{self, DH_LEN};
use crate::error::Error;
use crate::symmetric_state::{PROTOCOL_NAME, SymmetricState};
use crate::transport::TransportState;
use crate::types::{KeyPair, PublicKey, StaticSecret};

/// The current action the caller must take to advance the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeAction {
    /// Call `write_message()` to produce the next handshake message.
    WriteMessage,
    /// Call `read_message()` with the peer's handshake message.
    ReadMessage,
    /// The handshake is complete. Call `into_transport()`.
    Complete,
}

/// Internal state tracking which IK message we're on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    InitiatorWriteMsg1,
    InitiatorReadMsg2,
    ResponderReadMsg1,
    ResponderWriteMsg2,
    Complete,
}

/// A Noise IK handshake state machine.
///
/// Implements the fixed ciphersuite `Noise_IK_25519_ChaChaPoly_BLAKE2s`.
///
/// ## IK Pattern
///
/// ```text
/// IK:
///   <- s
///   ...
///   -> e, es, s, ss
///   <- e, ee, se
/// ```
pub struct Handshake {
    /// Option so that `into_transport()` can `.take()` it without
    /// preventing the rest of Drop from running.
    symmetric: Option<SymmetricState>,
    phase: Phase,
    is_initiator: bool,
    s: StaticSecret,
    s_pub: [u8; DH_LEN],
    rs: Option<[u8; DH_LEN]>,
    e: Option<StaticSecret>,
    e_pub: Option<[u8; DH_LEN]>,
    re: Option<[u8; DH_LEN]>,
}

impl Drop for Handshake {
    fn drop(&mut self) {
        self.s_pub.zeroize();
        if let Some(ref mut v) = self.e_pub {
            v.zeroize();
        }
        if let Some(ref mut v) = self.re {
            v.zeroize();
        }
        if let Some(ref mut v) = self.rs {
            v.zeroize();
        }
    }
}

impl Handshake {
    /// Create an initiator handshake.
    ///
    /// The initiator must know the responder's static public key beforehand.
    /// The `prologue` is mixed into the handshake hash but not encrypted;
    /// both sides must use the same prologue for the handshake to succeed.
    pub fn new_initiator(
        local: &KeyPair,
        remote_public: &PublicKey,
        prologue: &[u8],
    ) -> Result<Self, Error> {
        let mut symmetric = SymmetricState::initialize(PROTOCOL_NAME);

        // Mix prologue (per Noise spec Section 5.3, prologue is mixed first)
        symmetric.mix_hash(prologue);

        // IK pre-message: <- s (responder's static key is known)
        symmetric.mix_hash(remote_public.as_bytes());

        Ok(Self {
            symmetric: Some(symmetric),
            phase: Phase::InitiatorWriteMsg1,
            is_initiator: true,
            // Clone is necessary: the caller (e.g. quinn session) retains
            // the keypair in an Arc for reuse across sessions. Both copies
            // implement ZeroizeOnDrop and the extra copy is short-lived
            // (dropped when the handshake completes).
            s: local.secret.clone(),
            s_pub: *local.public.as_bytes(),
            rs: Some(*remote_public.as_bytes()),
            e: None,
            e_pub: None,
            re: None,
        })
    }

    /// Create a responder handshake.
    ///
    /// The responder does not know the initiator's public key beforehand.
    pub fn new_responder(local: &KeyPair, prologue: &[u8]) -> Result<Self, Error> {
        let mut symmetric = SymmetricState::initialize(PROTOCOL_NAME);

        // Mix prologue (per Noise spec Section 5.3, prologue is mixed first)
        symmetric.mix_hash(prologue);

        // IK pre-message: <- s (our own static key)
        symmetric.mix_hash(local.public.as_bytes());

        Ok(Self {
            symmetric: Some(symmetric),
            phase: Phase::ResponderReadMsg1,
            is_initiator: false,
            // See comment in new_initiator for clone rationale.
            s: local.secret.clone(),
            s_pub: *local.public.as_bytes(),
            rs: None,
            e: None,
            e_pub: None,
            re: None,
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
    ///
    /// `payload` is optional application data to encrypt within the message.
    /// Returns the number of bytes written to `out`.
    pub fn write_message(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        self.write_message_with_rng(payload, out, &mut OsRng)
    }

    /// Write the next handshake message with a specific RNG (useful for testing).
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
    ///
    /// Returns the number of decrypted payload bytes written to `out`.
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
            // Message 1: e(32) + encrypted_s(32+16tag) + payload_tag(16) = 96
            Phase::InitiatorWriteMsg1 => DH_LEN + DH_LEN + AEAD_TAG_LEN + AEAD_TAG_LEN,
            // Message 2: e(32) + payload_tag(16) = 48
            Phase::ResponderWriteMsg2 => DH_LEN + AEAD_TAG_LEN,
            _ => 0,
        }
    }

    /// Copy of the remote peer's static public key bytes, if known.
    pub fn remote_public_bytes(&self) -> Option<[u8; DH_LEN]> {
        self.rs
    }

    /// The current handshake hash.
    ///
    /// Returns `Err(Error::WrongState)` if called after `into_transport()`
    /// has consumed the handshake.
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
    ///
    /// Only available after the handshake is complete.
    /// Uses HKDF3(ck, label) and returns the third output.
    pub fn get_ask(&self, label: &[u8]) -> Result<[u8; HASH_LEN], Error> {
        if self.phase != Phase::Complete {
            return Err(Error::WrongState);
        }
        let ss = self.symmetric.as_ref().ok_or(Error::WrongState)?;
        let (_, _, ask) = hash::hkdf3(ss.chaining_key(), label);
        Ok(*ask)
    }

    /// Convert the completed handshake into a transport state.
    ///
    /// Per Noise spec: initiator gets (c1=send, c2=recv),
    /// responder gets (c1=recv, c2=send).
    pub fn into_transport(mut self) -> Result<TransportState, Error> {
        if self.phase != Phase::Complete {
            return Err(Error::WrongState);
        }

        let is_initiator = self.is_initiator;
        let symmetric = self.symmetric.take().ok_or(Error::WrongState)?;
        let (h, c1, c2) = symmetric.split();
        Ok(TransportState::new(h, c1, c2, is_initiator))
    }

    // ===== Message 1: initiator writes -> e, es, s, ss =====
    //
    // Layout: [e_pub(32)][encrypted_s_pub(32+16)][encrypted_payload(N+16)]

    fn write_msg1(
        &mut self,
        payload: &[u8],
        out: &mut [u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<usize, Error> {
        let overhead = self.next_message_overhead();
        let total = overhead
            .checked_add(payload.len())
            .ok_or(Error::BufferTooSmall)?;
        if out.len() < total {
            return Err(Error::BufferTooSmall);
        }

        let mut offset = 0;

        // -> e
        let (e_secret, e_pub) = x25519::generate_keypair(rng);
        out[offset..offset + DH_LEN].copy_from_slice(&e_pub);
        self.ss()?.mix_hash(&e_pub);
        self.e = Some(StaticSecret::from_dalek(e_secret));
        self.e_pub = Some(e_pub);
        offset += DH_LEN;

        // -> es: DH(e, rs)
        let rs = self.rs.ok_or(Error::WrongState)?;
        let shared_es = x25519::dh(
            self.e.as_ref().ok_or(Error::WrongState)?.inner(),
            &DalekPublicKey::from(rs),
        )?;
        self.ss()?.mix_key(shared_es.as_bytes());

        // -> s
        let s_pub = self.s_pub;
        let s_len = self.ss()?.encrypt_and_hash(&s_pub, &mut out[offset..])?;
        offset += s_len;

        // -> ss: DH(s, rs)
        let shared_ss = x25519::dh(self.s.inner(), &DalekPublicKey::from(rs))?;
        self.ss()?.mix_key(shared_ss.as_bytes());

        let p_len = self.ss()?.encrypt_and_hash(payload, &mut out[offset..])?;
        offset += p_len;

        self.phase = Phase::InitiatorReadMsg2;
        Ok(offset)
    }

    // ===== Message 1: responder reads -> e, es, s, ss =====

    fn read_msg1(&mut self, message: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let min_len = DH_LEN + DH_LEN + AEAD_TAG_LEN + AEAD_TAG_LEN;
        if message.len() < min_len {
            return Err(Error::BadMessage);
        }

        let mut offset = 0;

        // -> e
        let mut re = [0u8; DH_LEN];
        re.copy_from_slice(&message[offset..offset + DH_LEN]);
        self.ss()?.mix_hash(&re);
        self.re = Some(re);
        offset += DH_LEN;

        // -> es: DH(s, re)
        let shared_es = x25519::dh(self.s.inner(), &DalekPublicKey::from(re))?;
        self.ss()?.mix_key(shared_es.as_bytes());

        // -> s
        let encrypted_s_len = DH_LEN + AEAD_TAG_LEN;
        let mut rs_bytes = [0u8; DH_LEN];
        let s_len = self
            .ss()?
            .decrypt_and_hash(&message[offset..offset + encrypted_s_len], &mut rs_bytes)?;
        if s_len != DH_LEN {
            return Err(Error::BadMessage);
        }
        self.rs = Some(rs_bytes);
        offset += encrypted_s_len;

        // -> ss: DH(s, rs)
        let shared_ss = x25519::dh(self.s.inner(), &DalekPublicKey::from(rs_bytes))?;
        self.ss()?.mix_key(shared_ss.as_bytes());
        let remaining = &message[offset..];
        if remaining.len() < AEAD_TAG_LEN {
            return Err(Error::BadMessage);
        }
        let p_len = self.ss()?.decrypt_and_hash(remaining, out)?;

        self.phase = Phase::ResponderWriteMsg2;
        Ok(p_len)
    }

    // ===== Message 2: responder writes <- e, ee, se =====
    //
    // Layout: [e_pub(32)][encrypted_payload(N+16)]

    fn write_msg2(
        &mut self,
        payload: &[u8],
        out: &mut [u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<usize, Error> {
        let overhead = self.next_message_overhead();
        let total = overhead
            .checked_add(payload.len())
            .ok_or(Error::BufferTooSmall)?;
        if out.len() < total {
            return Err(Error::BufferTooSmall);
        }

        let mut offset = 0;

        // <- e
        let (e_secret, e_pub) = x25519::generate_keypair(rng);
        out[offset..offset + DH_LEN].copy_from_slice(&e_pub);
        self.ss()?.mix_hash(&e_pub);
        self.e = Some(StaticSecret::from_dalek(e_secret));
        self.e_pub = Some(e_pub);
        offset += DH_LEN;

        // <- ee: DH(e, re)
        let re = self.re.ok_or(Error::WrongState)?;
        let shared_ee = x25519::dh(
            self.e.as_ref().ok_or(Error::WrongState)?.inner(),
            &DalekPublicKey::from(re),
        )?;
        self.ss()?.mix_key(shared_ee.as_bytes());

        // <- se: DH(e, rs)
        let rs = self.rs.ok_or(Error::WrongState)?;
        let shared_se = x25519::dh(
            self.e.as_ref().ok_or(Error::WrongState)?.inner(),
            &DalekPublicKey::from(rs),
        )?;
        self.ss()?.mix_key(shared_se.as_bytes());

        let p_len = self.ss()?.encrypt_and_hash(payload, &mut out[offset..])?;
        offset += p_len;

        self.phase = Phase::Complete;
        Ok(offset)
    }

    // ===== Message 2: initiator reads <- e, ee, se =====

    fn read_msg2(&mut self, message: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let min_len = DH_LEN + AEAD_TAG_LEN;
        if message.len() < min_len {
            return Err(Error::BadMessage);
        }

        let mut offset = 0;

        // <- e
        let mut re = [0u8; DH_LEN];
        re.copy_from_slice(&message[offset..offset + DH_LEN]);
        self.ss()?.mix_hash(&re);
        self.re = Some(re);
        offset += DH_LEN;

        // <- ee: DH(e, re)
        let shared_ee = x25519::dh(
            self.e.as_ref().ok_or(Error::WrongState)?.inner(),
            &DalekPublicKey::from(re),
        )?;
        self.ss()?.mix_key(shared_ee.as_bytes());

        // <- se: DH(s, re)
        let shared_se = x25519::dh(self.s.inner(), &DalekPublicKey::from(re))?;
        self.ss()?.mix_key(shared_se.as_bytes());
        let remaining = &message[offset..];
        if remaining.len() < AEAD_TAG_LEN {
            return Err(Error::BadMessage);
        }
        let p_len = self.ss()?.decrypt_and_hash(remaining, out)?;

        self.phase = Phase::Complete;
        Ok(p_len)
    }
}
