use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::cipher_state::CipherState;
use crate::crypto::aead::AEAD_KEY_LEN;
use crate::crypto::hash::{self, HASH_LEN};
use crate::error::Error;

/// Noise SymmetricState — manages the chaining key and handshake hash.
///
/// Per Noise spec Section 5.2.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SymmetricState {
    cipher: CipherState,
    /// Chaining key (ck) — mixed with DH outputs via HKDF.
    ck: Zeroizing<[u8; HASH_LEN]>,
    /// Handshake hash (h) — accumulates all handshake data.
    h: [u8; HASH_LEN],
}

impl SymmetricState {
    /// Initialize the SymmetricState with a protocol name.
    ///
    /// Per Noise spec Section 5.2:
    /// - If protocol_name.len() <= HASH_LEN, pad with zeros
    /// - Otherwise, hash the protocol name
    pub fn initialize(protocol_name: &str) -> Self {
        let name_bytes = protocol_name.as_bytes();
        let h = if name_bytes.len() <= HASH_LEN {
            let mut h = [0u8; HASH_LEN];
            h[..name_bytes.len()].copy_from_slice(name_bytes);
            h
        } else {
            hash::hash(name_bytes)
        };

        Self {
            cipher: CipherState::empty(),
            ck: Zeroizing::new(h),
            h,
        }
    }

    /// Mix a key into the chaining key via HKDF.
    ///
    /// Per Noise spec: (ck, temp_k) = HKDF(ck, input_key_material, 2)
    /// Then: InitializeKey(temp_k)
    pub fn mix_key(&mut self, input_key_material: &[u8]) {
        let (new_ck, temp_k) = hash::hkdf2(&self.ck, input_key_material);
        *self.ck = *new_ck;

        let mut key = [0u8; AEAD_KEY_LEN];
        key.copy_from_slice(&*temp_k);
        self.cipher.initialize_key(key);
        key.zeroize();
    }

    /// Mix data into the handshake hash.
    ///
    /// Per Noise spec: h = HASH(h || data)
    pub fn mix_hash(&mut self, data: &[u8]) {
        self.h = hash::hash_two(&self.h, data);
    }

    /// Encrypt plaintext and mix the ciphertext into the hash.
    ///
    /// Per Noise spec: ciphertext = EncryptWithAd(h, plaintext), then MixHash(ciphertext)
    pub fn encrypt_and_hash(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let len = self.cipher.encrypt_with_ad(&self.h, plaintext, out)?;
        self.mix_hash(&out[..len]);
        Ok(len)
    }

    /// Decrypt ciphertext and mix it into the hash.
    ///
    /// Per Noise spec: `plaintext = DecryptWithAd(h, ciphertext)`, then `MixHash(ciphertext)`.
    /// The current hash is used as AD *before* mixing in the ciphertext.
    pub fn decrypt_and_hash(&mut self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let len = self.cipher.decrypt_with_ad(&self.h, ciphertext, out)?;
        self.mix_hash(ciphertext);
        Ok(len)
    }

    /// Split into two CipherStates for transport mode.
    ///
    /// Per Noise spec Section 5.2:
    /// (temp_k1, temp_k2) = HKDF(ck, "", 2)
    /// c1.InitializeKey(temp_k1), c2.InitializeKey(temp_k2)
    pub fn split(self) -> ([u8; HASH_LEN], CipherState, CipherState) {
        let (temp_k1, temp_k2) = hash::hkdf2(&self.ck, &[]);

        let mut c1 = CipherState::empty();
        let mut key1 = [0u8; AEAD_KEY_LEN];
        key1.copy_from_slice(&*temp_k1);
        c1.initialize_key(key1);
        key1.zeroize();

        let mut c2 = CipherState::empty();
        let mut key2 = [0u8; AEAD_KEY_LEN];
        key2.copy_from_slice(&*temp_k2);
        c2.initialize_key(key2);
        key2.zeroize();

        let h = self.h;
        (h, c1, c2)
    }

    /// Get the current handshake hash.
    pub fn handshake_hash(&self) -> &[u8; HASH_LEN] {
        &self.h
    }

    /// Get the current chaining key (for ASK derivation).
    pub fn chaining_key(&self) -> &[u8; HASH_LEN] {
        &self.ck
    }

    /// The current encryption overhead.
    #[allow(dead_code)]
    pub fn overhead(&self) -> usize {
        self.cipher.overhead()
    }
}
