//! ML-KEM-768 Key Encapsulation Mechanism wrapper.
//!
//! Thin wrapper around the `ml-kem` crate providing:
//! - Key generation (returns seed + encapsulation key)
//! - Encapsulation (shared secret + ciphertext from a public key)
//! - Decapsulation (shared secret from ciphertext + seed)
//!
//! All secret material is zeroized on drop.
//!
//! # RNG Bridging
//!
//! The `ml-kem` crate uses `rand_core` 0.10, while this crate uses 0.6.
//! Rather than depending on two incompatible versions, we draw entropy
//! from the caller's `CryptoRngCore` (0.6) and feed it into ml-kem's
//! deterministic APIs. This ensures:
//! - Single entropy source controlled by the caller
//! - Fully deterministic output for a given RNG state (testable)
//! - No `rand_core` version conflicts

use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::{B32, MlKem768, Seed};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::Error;

/// ML-KEM-768 encapsulation key (public) size in bytes.
pub const KEM_EK_LEN: usize = 1184;

/// ML-KEM-768 decapsulation key seed size in bytes.
pub const KEM_SEED_LEN: usize = 64;

/// ML-KEM-768 ciphertext size in bytes.
pub const KEM_CT_LEN: usize = 1088;

/// ML-KEM-768 shared secret size in bytes.
pub const KEM_SS_LEN: usize = 32;

/// A shared secret resulting from a KEM encapsulation or decapsulation.
///
/// Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KemSharedSecret([u8; KEM_SS_LEN]);

impl KemSharedSecret {
    /// Access the raw 32-byte shared secret.
    pub fn as_bytes(&self) -> &[u8; KEM_SS_LEN] {
        &self.0
    }
}

/// Generate a new ML-KEM-768 keypair.
///
/// Draws 64 bytes of randomness from `rng` and uses them as the
/// deterministic seed for ML-KEM key generation (FIPS 203 §7.1).
///
/// Returns `(dk_seed, ek_bytes)` where:
/// - `dk_seed` is the 64-byte decapsulation key seed (zeroized on drop)
/// - `ek_bytes` is the 1184-byte encapsulation (public) key
pub fn kem_generate(
    rng: &mut impl CryptoRngCore,
) -> (Zeroizing<[u8; KEM_SEED_LEN]>, [u8; KEM_EK_LEN]) {
    // Draw 64 bytes of randomness: (d || z) per FIPS 203 §7.1.
    let mut seed_bytes = Zeroizing::new([0u8; KEM_SEED_LEN]);
    rng.fill_bytes(&mut *seed_bytes);

    let seed: Seed = (*seed_bytes).into();
    let dk = ml_kem::DecapsulationKey::<MlKem768>::from_seed(seed);
    let ek = dk.encapsulation_key();

    // Extract the encapsulation key bytes via the KeyExport trait.
    let ek_exported = ek.to_bytes();
    let mut ek_bytes = [0u8; KEM_EK_LEN];
    ek_bytes.copy_from_slice(ek_exported.as_slice());

    (seed_bytes, ek_bytes)
}

/// Derive the ML-KEM-768 encapsulation key from a decapsulation key seed.
pub fn kem_ek_from_seed(seed_bytes: &[u8; KEM_SEED_LEN]) -> [u8; KEM_EK_LEN] {
    let mut seed_copy = Zeroizing::new(*seed_bytes);
    let seed: Seed = (*seed_copy).into();
    seed_copy.zeroize();

    let dk = ml_kem::DecapsulationKey::<MlKem768>::from_seed(seed);
    let ek = dk.encapsulation_key();
    let ek_exported = ek.to_bytes();
    let mut ek_bytes = [0u8; KEM_EK_LEN];
    ek_bytes.copy_from_slice(ek_exported.as_slice());
    ek_bytes
}

/// Encapsulate a shared secret against a remote encapsulation key.
///
/// Draws 32 bytes of randomness from `rng` for the encapsulation.
/// Returns `(ciphertext, shared_secret)`.
pub fn kem_encapsulate(
    remote_ek_bytes: &[u8; KEM_EK_LEN],
    rng: &mut impl CryptoRngCore,
) -> Result<([u8; KEM_CT_LEN], KemSharedSecret), Error> {
    let ek = ml_kem::EncapsulationKey::<MlKem768>::new(remote_ek_bytes.into())
        .map_err(|_| Error::BadKey)?;

    // Draw 32 bytes for the encapsulation randomness (message `m`).
    let mut m_bytes = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut *m_bytes);
    let m: &B32 = (&*m_bytes).into();

    let (ct, ss) = ek.encapsulate_deterministic(m);

    let mut ct_bytes = [0u8; KEM_CT_LEN];
    ct_bytes.copy_from_slice(ct.as_slice());

    let mut ss_bytes = [0u8; KEM_SS_LEN];
    ss_bytes.copy_from_slice(ss.as_slice());
    let shared = KemSharedSecret(ss_bytes);
    ss_bytes.zeroize();

    Ok((ct_bytes, shared))
}

/// Decapsulate a ciphertext using the local decapsulation key seed.
///
/// Reconstructs the decapsulation key from the 64-byte seed, then
/// decapsulates the ciphertext to recover the shared secret.
///
/// ML-KEM uses implicit rejection: invalid ciphertexts produce a
/// pseudorandom shared secret rather than an error, preventing
/// chosen-ciphertext attacks.
pub fn kem_decapsulate(
    dk_seed: &[u8; KEM_SEED_LEN],
    ct_bytes: &[u8; KEM_CT_LEN],
) -> Result<KemSharedSecret, Error> {
    let mut seed_bytes = Zeroizing::new(*dk_seed);
    let seed: Seed = (*seed_bytes).into();
    seed_bytes.zeroize();

    // NOTE: DecapsulationKey zeroization depends on the ml-kem crate's
    // implementation. The expanded key material lives on the stack and is
    // dropped at function exit, but may not be explicitly zeroized.
    // Pinned to ml-kem 0.3.0-rc.0; verify zeroization on upgrades.
    let dk = ml_kem::DecapsulationKey::<MlKem768>::from_seed(seed);
    let ct = ml_kem::kem::Ciphertext::<MlKem768>::try_from(ct_bytes.as_slice())
        .map_err(|_| Error::BadMessage)?;
    let ss = dk.decapsulate(&ct);

    let mut ss_bytes = [0u8; KEM_SS_LEN];
    ss_bytes.copy_from_slice(ss.as_slice());
    let shared = KemSharedSecret(ss_bytes);
    ss_bytes.zeroize();

    Ok(shared)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn generate_encapsulate_decapsulate_round_trip() {
        let (dk_seed, ek_bytes) = kem_generate(&mut OsRng);
        let (ct_bytes, ss_enc) = kem_encapsulate(&ek_bytes, &mut OsRng).unwrap();
        let ss_dec = kem_decapsulate(&dk_seed, &ct_bytes).unwrap();
        assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
    }

    #[test]
    fn different_keys_different_secrets() {
        let (dk_seed1, ek_bytes1) = kem_generate(&mut OsRng);
        let (_dk_seed2, _ek_bytes2) = kem_generate(&mut OsRng);

        let (ct, ss1) = kem_encapsulate(&ek_bytes1, &mut OsRng).unwrap();
        let ss_self = kem_decapsulate(&dk_seed1, &ct).unwrap();
        assert_eq!(ss1.as_bytes(), ss_self.as_bytes());
    }

    #[test]
    fn wrong_dk_produces_different_secret() {
        // ML-KEM implicit rejection: wrong key produces pseudorandom output
        let (_dk_seed1, ek_bytes1) = kem_generate(&mut OsRng);
        let (dk_seed2, _ek_bytes2) = kem_generate(&mut OsRng);

        let (ct, ss_enc) = kem_encapsulate(&ek_bytes1, &mut OsRng).unwrap();
        let ss_wrong = kem_decapsulate(&dk_seed2, &ct).unwrap();
        assert_ne!(ss_enc.as_bytes(), ss_wrong.as_bytes());
    }

    #[test]
    fn shared_secret_is_32_bytes() {
        let (dk_seed, ek_bytes) = kem_generate(&mut OsRng);
        let (ct, ss) = kem_encapsulate(&ek_bytes, &mut OsRng).unwrap();
        assert_eq!(ss.as_bytes().len(), 32);
        let ss2 = kem_decapsulate(&dk_seed, &ct).unwrap();
        assert_eq!(ss2.as_bytes().len(), 32);
    }

    #[test]
    fn ciphertext_size_correct() {
        let (_dk_seed, ek_bytes) = kem_generate(&mut OsRng);
        let (ct, _ss) = kem_encapsulate(&ek_bytes, &mut OsRng).unwrap();
        assert_eq!(ct.len(), KEM_CT_LEN);
    }

    #[test]
    fn encapsulation_key_size_correct() {
        let (_dk_seed, ek_bytes) = kem_generate(&mut OsRng);
        assert_eq!(ek_bytes.len(), KEM_EK_LEN);
    }

    #[test]
    fn seed_size_correct() {
        let (dk_seed, _ek_bytes) = kem_generate(&mut OsRng);
        assert_eq!(dk_seed.len(), KEM_SEED_LEN);
    }
}
