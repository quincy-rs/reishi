//! ML-KEM-768 and the small KDF-SEEC profile used by the PQ handshakes.
//!
//! The profile combines fresh session coins with an independent persistent
//! secret using domain-separated HMAC-BLAKE2s and HKDF expansion. It protects
//! predictable or exposed coins while that persistent key remains secret.
//!
//! NOTE: This stateless profile does not protect against maliciously chosen or
//! repeating entropy. Upgrade to stateful or hardware-backed SEEC if that threat
//! is in scope; strict PRP-SEEC would require a new wide-block primitive.
//!
//! NOTE: Reconstructing an ML-KEM decapsulation key expands secret material in
//! memory. The required `ml-kem/zeroize` feature wipes that material on drop;
//! keep the feature enabled and re-audit this assumption on dependency upgrades.

use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::{B32, MlKem768, Seed};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::hash;
use crate::error::Error;

/// Serialized length of an ML-KEM-768 encapsulation key.
pub const KEM_EK_LEN: usize = 1184;

/// Serialized length of the seed used to reconstruct an ML-KEM-768 secret key.
pub const KEM_SEED_LEN: usize = 64;

/// Serialized length of an ML-KEM-768 ciphertext.
pub const KEM_CT_LEN: usize = 1088;

/// Length of an ML-KEM-768 shared secret.
pub const KEM_SS_LEN: usize = 32;

/// Domain separator for the local KDF-SEEC construction.
const SEEC_DOMAIN: &[u8] = b"reishi KDF-SEEC v1";

/// HKDF expansion label applied after the HMAC-BLAKE2s extraction step.
const SEEC_EXPAND_INFO: &[u8] = b"reishi KDF-SEEC output";

/// Purpose label used only for ephemeral ML-KEM key generation.
const EPHEMERAL_KEM_PURPOSE: &[u8] = b"ephemeral-key-generation";

/// Purpose label used only for ephemeral X25519 secret generation.
const EPHEMERAL_DH_PURPOSE: &[u8] = b"ephemeral-dh-key-generation";

/// Purpose label used only for ML-KEM encapsulation.
const ENCAPSULATION_PURPOSE: &[u8] = b"encapsulation";

/// Zeroizing shared secret returned by ML-KEM encapsulation or decapsulation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KemSharedSecret([u8; KEM_SS_LEN]);

impl KemSharedSecret {
    /// Borrow the shared secret for immediate transcript-key mixing.
    pub fn as_bytes(&self) -> &[u8; KEM_SS_LEN] {
        &self.0
    }
}

/// Static ML-KEM generation deliberately uses the caller's secure RNG directly.
pub fn kem_generate(
    rng: &mut impl CryptoRngCore,
) -> (Zeroizing<[u8; KEM_SEED_LEN]>, [u8; KEM_EK_LEN]) {
    let mut seed = Zeroizing::new([0u8; KEM_SEED_LEN]);
    rng.fill_bytes(&mut *seed);

    let encapsulation_key = kem_ek_from_seed(&seed);

    (seed, encapsulation_key)
}

/// Reconstruct the public encapsulation key belonging to an ML-KEM seed.
pub fn kem_ek_from_seed(seed_bytes: &[u8; KEM_SEED_LEN]) -> [u8; KEM_EK_LEN] {
    let seed: Seed = (*seed_bytes).into();
    let decapsulation_key = ml_kem::DecapsulationKey::<MlKem768>::from_seed(seed);
    let exported_key = decapsulation_key.encapsulation_key().to_bytes();
    let mut encapsulation_key = [0u8; KEM_EK_LEN];

    encapsulation_key.copy_from_slice(exported_key.as_slice());

    encapsulation_key
}

/// Generate an ephemeral ML-KEM keypair with hardened session coins.
pub(crate) fn kem_generate_ephemeral(
    seec_key: &[u8; 32],
    suite: &str,
    rng: &mut impl CryptoRngCore,
) -> (Zeroizing<[u8; KEM_SEED_LEN]>, [u8; KEM_EK_LEN]) {
    let seed = seec_random::<KEM_SEED_LEN>(seec_key, suite, EPHEMERAL_KEM_PURPOSE, rng);
    let encapsulation_key = kem_ek_from_seed(&seed);

    (seed, encapsulation_key)
}

/// Generate a suite-bound X25519 ephemeral secret from hardened session coins.
pub(crate) fn seec_ephemeral_dh_secret(
    seec_key: &[u8; 32],
    suite: &str,
    rng: &mut impl CryptoRngCore,
) -> Zeroizing<[u8; 32]> {
    seec_random::<32>(seec_key, suite, EPHEMERAL_DH_PURPOSE, rng)
}

/// Encapsulate with hardened session coins bound to the selected suite.
pub(crate) fn kem_encapsulate(
    remote_encapsulation_key: &[u8; KEM_EK_LEN],
    seec_key: &[u8; 32],
    suite: &str,
    rng: &mut impl CryptoRngCore,
) -> Result<([u8; KEM_CT_LEN], KemSharedSecret), Error> {
    let randomness = seec_random::<32>(seec_key, suite, ENCAPSULATION_PURPOSE, rng);

    kem_encapsulate_deterministic(remote_encapsulation_key, &randomness)
}

/// Perform deterministic ML-KEM encapsulation with already-hardened randomness.
fn kem_encapsulate_deterministic(
    remote_encapsulation_key: &[u8; KEM_EK_LEN],
    randomness: &[u8; 32],
) -> Result<([u8; KEM_CT_LEN], KemSharedSecret), Error> {
    let encapsulation_key =
        ml_kem::EncapsulationKey::<MlKem768>::new(remote_encapsulation_key.into())
            .map_err(|_| Error::BadKey)?;
    let encapsulation_randomness: &B32 = randomness.into();
    let (ciphertext, mut ml_kem_shared_secret) =
        encapsulation_key.encapsulate_deterministic(encapsulation_randomness);

    let mut ciphertext_bytes = [0u8; KEM_CT_LEN];
    ciphertext_bytes.copy_from_slice(ciphertext.as_slice());

    let mut shared_secret = [0u8; KEM_SS_LEN];
    shared_secret.copy_from_slice(ml_kem_shared_secret.as_slice());

    ml_kem_shared_secret.zeroize();

    Ok((ciphertext_bytes, KemSharedSecret(shared_secret)))
}

/// Recover an ML-KEM shared secret from a ciphertext and static or ephemeral seed.
pub(crate) fn kem_decapsulate(
    decapsulation_seed: &[u8; KEM_SEED_LEN],
    ciphertext: &[u8; KEM_CT_LEN],
) -> Result<KemSharedSecret, Error> {
    let seed: Seed = (*decapsulation_seed).into();
    let decapsulation_key = ml_kem::DecapsulationKey::<MlKem768>::from_seed(seed);
    let ciphertext = ml_kem::kem::Ciphertext::<MlKem768>::try_from(ciphertext.as_slice())
        .map_err(|_| Error::BadMessage)?;
    let mut ml_kem_shared_secret = decapsulation_key.decapsulate(&ciphertext);

    let mut shared_secret = [0u8; KEM_SS_LEN];
    shared_secret.copy_from_slice(ml_kem_shared_secret.as_slice());

    ml_kem_shared_secret.zeroize();

    Ok(KemSharedSecret(shared_secret))
}

/// Draw fresh coins and harden them for one suite-specific cryptographic purpose.
fn seec_random<const N: usize>(
    seec_key: &[u8; 32],
    suite: &str,
    purpose: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Zeroizing<[u8; N]> {
    let mut coins = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut *coins);

    seec_derive(seec_key, suite, purpose, &coins)
}

/// Derive deterministic KDF-SEEC output for a fixed key, suite, purpose, and coins.
fn seec_derive<const N: usize>(
    seec_key: &[u8; 32],
    suite: &str,
    purpose: &[u8],
    coins: &[u8; 32],
) -> Zeroizing<[u8; N]> {
    let separators = [0u8];
    let prk = hash::hmac_multi(
        seec_key,
        &[
            SEEC_DOMAIN,
            &separators,
            suite.as_bytes(),
            &separators,
            purpose,
            &separators,
            coins,
        ],
    );

    let mut output = Zeroizing::new([0u8; N]);
    assert!(
        hash::hkdf_expand(&prk, SEEC_EXPAND_INFO, &mut *output),
        "KDF-SEEC output exceeds the HKDF expansion limit",
    );

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_round_trip() {
        let (decapsulation_seed, encapsulation_key) = kem_generate(&mut rand_core::OsRng);
        let (ciphertext, sent_secret) = kem_encapsulate(
            &encapsulation_key,
            &[7u8; 32],
            "test-suite",
            &mut rand_core::OsRng,
        )
        .unwrap();
        let received_secret = kem_decapsulate(&decapsulation_seed, &ciphertext).unwrap();

        assert_eq!(sent_secret.as_bytes(), received_secret.as_bytes());
    }

    #[test]
    fn seec_separates_static_key_coins_suite_and_purpose() {
        let static_seec_key = [1u8; 32];
        let other_static_seec_key = [3u8; 32];
        let coins = [2u8; 32];
        let other_coins = [4u8; 32];
        let baseline = seec_derive::<64>(&static_seec_key, "pq", EPHEMERAL_KEM_PURPOSE, &coins);

        assert_ne!(
            *baseline,
            *seec_derive::<64>(&other_static_seec_key, "pq", EPHEMERAL_KEM_PURPOSE, &coins,),
        );

        assert_ne!(
            *baseline,
            *seec_derive::<64>(&static_seec_key, "pq", EPHEMERAL_KEM_PURPOSE, &other_coins,),
        );

        assert_ne!(
            *baseline,
            *seec_derive::<64>(&static_seec_key, "hybrid", EPHEMERAL_KEM_PURPOSE, &coins,),
        );

        assert_ne!(
            &baseline[..32],
            &seec_derive::<32>(&static_seec_key, "pq", ENCAPSULATION_PURPOSE, &coins,)[..],
        );

        assert_ne!(
            &baseline[..32],
            &seec_derive::<32>(&static_seec_key, "pq", EPHEMERAL_DH_PURPOSE, &coins)[..],
        );
    }

    #[test]
    #[should_panic(expected = "KDF-SEEC output exceeds the HKDF expansion limit")]
    fn seec_rejects_oversized_output() {
        let _ = seec_derive::<8161>(&[1u8; 32], "pq", EPHEMERAL_KEM_PURPOSE, &[2u8; 32]);
    }

    #[test]
    fn seec_fixed_vector() {
        let output = seec_derive::<64>(
            &[0x11u8; 32],
            "Noise_pqIKkc_MLKEM768_ChaChaPoly_BLAKE2s",
            EPHEMERAL_KEM_PURPOSE,
            &[0x22u8; 32],
        );

        assert_eq!(
            *output,
            [
                65, 119, 121, 220, 145, 102, 164, 44, 68, 50, 237, 112, 39, 116, 187, 244, 221,
                198, 172, 1, 224, 235, 252, 233, 142, 228, 216, 208, 228, 90, 50, 11, 85, 193, 177,
                132, 139, 176, 39, 126, 240, 48, 63, 240, 122, 128, 170, 16, 196, 86, 155, 217,
                176, 213, 68, 1, 183, 121, 148, 237, 20, 187, 224, 11,
            ],
        );
    }
}
