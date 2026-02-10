use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::aead::{self, AEAD_KEY_LEN, AEAD_TAG_LEN};
use crate::error::Error;

/// Noise CipherState — manages an AEAD key and a nonce counter.
///
/// Per Noise spec Section 5.1.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CipherState {
    /// The AEAD key, or `None` if uninitialized.
    key: Option<[u8; AEAD_KEY_LEN]>,
    /// Nonce counter, incremented after each encryption/decryption.
    #[zeroize(skip)]
    nonce: u64,
}

impl CipherState {
    /// Create an empty (uninitialized) CipherState.
    pub fn empty() -> Self {
        Self {
            key: None,
            nonce: 0,
        }
    }

    /// Initialize with a key, resetting the nonce counter to zero.
    pub fn initialize_key(&mut self, key: [u8; AEAD_KEY_LEN]) {
        self.key = Some(key);
        self.nonce = 0;
    }

    /// Whether this CipherState has a key set.
    #[allow(dead_code)]
    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }

    /// Encrypt plaintext with associated data.
    ///
    /// If no key is set, copies plaintext to output unchanged (Noise spec behavior).
    /// Returns the number of bytes written.
    pub fn encrypt_with_ad(
        &mut self,
        ad: &[u8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        match &self.key {
            None => {
                if out.len() < plaintext.len() {
                    return Err(Error::BufferTooSmall);
                }
                out[..plaintext.len()].copy_from_slice(plaintext);
                Ok(plaintext.len())
            }
            Some(key) => {
                if self.nonce == u64::MAX {
                    // Nonce 2^64-1 is reserved for rekey (Noise spec §11.3)
                    return Err(Error::NonceExhausted);
                }
                let needed = plaintext.len() + AEAD_TAG_LEN;
                if out.len() < needed {
                    return Err(Error::BufferTooSmall);
                }
                out[..plaintext.len()].copy_from_slice(plaintext);
                let len = aead::encrypt_in_place(key, self.nonce, ad, out, plaintext.len())?;
                self.nonce += 1;
                Ok(len)
            }
        }
    }

    /// Decrypt ciphertext with associated data.
    ///
    /// If no key is set, copies ciphertext to output unchanged (Noise spec behavior).
    /// Returns the number of plaintext bytes written.
    pub fn decrypt_with_ad(
        &mut self,
        ad: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        match &self.key {
            None => {
                if out.len() < ciphertext.len() {
                    return Err(Error::BufferTooSmall);
                }
                out[..ciphertext.len()].copy_from_slice(ciphertext);
                Ok(ciphertext.len())
            }
            Some(key) => {
                if self.nonce == u64::MAX {
                    // Nonce 2^64-1 is reserved for rekey (Noise spec §11.3)
                    return Err(Error::NonceExhausted);
                }
                if ciphertext.len() < AEAD_TAG_LEN {
                    return Err(Error::BadMessage);
                }
                let plaintext_len = ciphertext.len() - AEAD_TAG_LEN;
                if out.len() < plaintext_len {
                    return Err(Error::BufferTooSmall);
                }
                // In-place decryption needs the full ciphertext (including tag)
                // in the buffer; use a temp Vec when `out` can't hold it.
                if out.len() >= ciphertext.len() {
                    out[..ciphertext.len()].copy_from_slice(ciphertext);
                    let len = aead::decrypt_in_place(key, self.nonce, ad, out, ciphertext.len())?;
                    self.nonce += 1;
                    Ok(len)
                } else {
                    let mut tmp = Zeroizing::new(vec![0u8; ciphertext.len()]);
                    tmp.copy_from_slice(ciphertext);
                    let len =
                        aead::decrypt_in_place(key, self.nonce, ad, &mut tmp, ciphertext.len())?;
                    out[..len].copy_from_slice(&tmp[..len]);
                    self.nonce += 1;
                    Ok(len)
                }
            }
        }
    }

    /// Rekey per Noise spec Section 11.3. Does not reset the nonce counter.
    pub fn rekey(&mut self) -> Result<(), Error> {
        if let Some(ref mut key) = self.key {
            *key = aead::rekey(key)?;
        }
        Ok(())
    }

    /// The overhead added by encryption (0 if no key, AEAD_TAG_LEN otherwise).
    #[allow(dead_code)]
    pub fn overhead(&self) -> usize {
        if self.has_key() { AEAD_TAG_LEN } else { 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_key_passthrough() {
        let mut cs = CipherState::empty();
        let plaintext = b"hello";
        let mut out = [0u8; 32];

        let len = cs.encrypt_with_ad(b"", plaintext, &mut out).unwrap();
        assert_eq!(len, plaintext.len());
        assert_eq!(&out[..len], plaintext);
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = [0x42u8; AEAD_KEY_LEN];
        let mut encrypt_cs = CipherState::empty();
        encrypt_cs.initialize_key(key);
        let mut decrypt_cs = CipherState::empty();
        decrypt_cs.initialize_key(key);

        let plaintext = b"noise protocol";
        let mut ct = [0u8; 128];
        let ct_len = encrypt_cs
            .encrypt_with_ad(b"ad", plaintext, &mut ct)
            .unwrap();

        let mut pt = [0u8; 128];
        let pt_len = decrypt_cs
            .decrypt_with_ad(b"ad", &ct[..ct_len], &mut pt)
            .unwrap();
        assert_eq!(&pt[..pt_len], plaintext);
    }

    #[test]
    fn encrypt_buffer_too_small() {
        let key = [0x42u8; AEAD_KEY_LEN];
        let mut cs = CipherState::empty();
        cs.initialize_key(key);

        let plaintext = b"hello";
        let mut out = [0u8; 4]; // too small (needs 5 + 16)
        let result = cs.encrypt_with_ad(b"", plaintext, &mut out);
        assert_eq!(result, Err(Error::BufferTooSmall));
    }

    #[test]
    fn decrypt_buffer_too_small() {
        let key = [0x42u8; AEAD_KEY_LEN];
        let mut enc = CipherState::empty();
        enc.initialize_key(key);
        let mut dec = CipherState::empty();
        dec.initialize_key(key);

        let plaintext = b"hello world test";
        let mut ct = [0u8; 128];
        let ct_len = enc.encrypt_with_ad(b"", plaintext, &mut ct).unwrap();

        // Output buffer can hold plaintext but not ciphertext+tag: exercises temp Vec path
        let mut out = [0u8; 16]; // exactly plaintext len, smaller than ct_len
        let pt_len = dec.decrypt_with_ad(b"", &ct[..ct_len], &mut out).unwrap();
        assert_eq!(&out[..pt_len], plaintext);
    }

    #[test]
    fn decrypt_truncated_ciphertext() {
        let key = [0x42u8; AEAD_KEY_LEN];
        let mut cs = CipherState::empty();
        cs.initialize_key(key);

        // Less than a single AEAD tag
        let result = cs.decrypt_with_ad(b"", &[0u8; 8], &mut [0u8; 64]);
        assert_eq!(result, Err(Error::BadMessage));
    }

    #[test]
    fn rekey_changes_key() {
        let key = [0x42u8; AEAD_KEY_LEN];
        let mut cs1 = CipherState::empty();
        cs1.initialize_key(key);
        let mut cs2 = CipherState::empty();
        cs2.initialize_key(key);

        cs1.rekey().unwrap();
        cs2.rekey().unwrap();

        // After rekeying both with the same original key, they should still
        // agree (both produce the same new key)
        let mut ct = [0u8; 128];
        let mut pt = [0u8; 128];
        let ct_len = cs1.encrypt_with_ad(b"", b"after rekey", &mut ct).unwrap();
        let pt_len = cs2.decrypt_with_ad(b"", &ct[..ct_len], &mut pt).unwrap();
        assert_eq!(&pt[..pt_len], b"after rekey");
    }

    #[test]
    fn no_key_decrypt_passthrough() {
        let mut cs = CipherState::empty();
        let ciphertext = b"pass through";
        let mut out = [0u8; 32];

        let len = cs.decrypt_with_ad(b"", ciphertext, &mut out).unwrap();
        assert_eq!(len, ciphertext.len());
        assert_eq!(&out[..len], ciphertext);
    }

    #[test]
    fn overhead_with_and_without_key() {
        let mut cs = CipherState::empty();
        assert_eq!(cs.overhead(), 0);

        cs.initialize_key([0u8; AEAD_KEY_LEN]);
        assert_eq!(cs.overhead(), AEAD_TAG_LEN);
    }

    #[test]
    fn nonce_increments() {
        let key = [0x42u8; AEAD_KEY_LEN];
        let mut cs1 = CipherState::empty();
        cs1.initialize_key(key);
        let mut cs2 = CipherState::empty();
        cs2.initialize_key(key);

        let mut ct1 = [0u8; 128];
        let mut ct2 = [0u8; 128];
        let len1 = cs1.encrypt_with_ad(b"", b"a", &mut ct1).unwrap();
        let len2 = cs1.encrypt_with_ad(b"", b"a", &mut ct2).unwrap();

        // Same plaintext, different nonce -> different ciphertext
        assert_ne!(&ct1[..len1], &ct2[..len2]);
    }
}
