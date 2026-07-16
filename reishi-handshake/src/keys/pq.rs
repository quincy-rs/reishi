//! Static key types for the KEM-only `pqIK` and hybrid IK handshakes.
//!
//! KEM-only secrets serialize as `ml_kem_seed || seec_key`. Hybrid secrets
//! prepend the X25519 secret. The independent SEEC key hardens per-session
//! randomness and must be persisted with the static ML-KEM seed.

use core::hash::{Hash, Hasher};

use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use super::standard::{KeyPair, PublicKey, StaticSecret};
use crate::crypto::pq::{KEM_EK_LEN, KEM_SEED_LEN, kem_ek_from_seed, kem_generate};

/// Length of the persistent KDF-SEEC key stored beside each ML-KEM secret.
pub(crate) const SEEC_KEY_LEN: usize = 32;

/// An ML-KEM-768 encapsulation key.
#[derive(Clone)]
pub struct EncapsulationKey([u8; Self::LEN]);

impl EncapsulationKey {
    /// Serialized length of an ML-KEM-768 encapsulation key.
    pub const LEN: usize = KEM_EK_LEN;

    /// Construct an encapsulation key from its fixed-width wire encoding.
    pub fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the fixed-width wire encoding of this encapsulation key.
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl AsRef<[u8; Self::LEN]> for EncapsulationKey {
    fn as_ref(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl AsRef<[u8]> for EncapsulationKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq for EncapsulationKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for EncapsulationKey {}

impl Hash for EncapsulationKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl core::fmt::Debug for EncapsulationKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "EncapsulationKey([{:02x}{:02x}..{}B])",
            self.0[0],
            self.0[1],
            Self::LEN,
        )
    }
}

impl Drop for EncapsulationKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// KEM-only static secret: ML-KEM seed followed by an independent SEEC key.
pub struct PqStaticSecret {
    /// Seed used to reconstruct the ML-KEM decapsulation key.
    pub(crate) kem_seed: Zeroizing<[u8; KEM_SEED_LEN]>,

    /// Independent persistent key used to harden session randomness.
    pub(crate) seec_key: Zeroizing<[u8; SEEC_KEY_LEN]>,
}

impl PqStaticSecret {
    /// Serialized length of `ml_kem_seed || seec_key`.
    pub const LEN: usize = KEM_SEED_LEN + SEEC_KEY_LEN;
}

/// KEM-only ML-KEM-768 public key.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct PqPublicKey {
    /// ML-KEM-768 encapsulation key used by the remote peer.
    pub(crate) kem_ek: EncapsulationKey,
}

impl PqPublicKey {
    /// Serialized length of a KEM-only public key.
    pub const LEN: usize = EncapsulationKey::LEN;

    /// Borrow the ML-KEM-768 encapsulation key.
    pub fn kem_ek(&self) -> &EncapsulationKey {
        &self.kem_ek
    }

    /// Construct a KEM-only public key from its wire encoding.
    pub fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self {
            kem_ek: EncapsulationKey::from_bytes(bytes),
        }
    }

    /// Serialize this KEM-only public key for storage or transport.
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        *self.kem_ek.as_bytes()
    }
}

/// KEM-only static keypair for `pqIK`.
pub struct PqKeyPair {
    /// Secret ML-KEM seed and persistent SEEC key.
    pub secret: PqStaticSecret,

    /// Corresponding ML-KEM encapsulation key.
    pub public: PqPublicKey,
}

impl PqKeyPair {
    /// Generate a KEM-only static keypair and an independent persistent SEEC key.
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let (kem_seed, kem_ek) = kem_generate(rng);

        let mut seec_key = Zeroizing::new([0u8; SEEC_KEY_LEN]);
        rng.fill_bytes(&mut *seec_key);

        Self {
            secret: PqStaticSecret { kem_seed, seec_key },

            public: PqPublicKey {
                kem_ek: EncapsulationKey::from_bytes(kem_ek),
            },
        }
    }

    /// Reconstruct the public key belonging to an existing static secret.
    pub fn from_secret(secret: PqStaticSecret) -> Self {
        let kem_ek = kem_ek_from_seed(&secret.kem_seed);

        Self {
            secret,

            public: PqPublicKey {
                kem_ek: EncapsulationKey::from_bytes(kem_ek),
            },
        }
    }

    /// Restore a keypair from `ml_kem_seed || seec_key`.
    pub fn from_secret_bytes(bytes: &[u8; PqStaticSecret::LEN]) -> Self {
        let mut kem_seed = Zeroizing::new([0u8; KEM_SEED_LEN]);
        kem_seed.copy_from_slice(&bytes[..KEM_SEED_LEN]);

        let mut seec_key = Zeroizing::new([0u8; SEEC_KEY_LEN]);
        seec_key.copy_from_slice(&bytes[KEM_SEED_LEN..]);

        Self::from_secret(PqStaticSecret { kem_seed, seec_key })
    }

    /// Export `ml_kem_seed || seec_key` in zeroizing storage.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; PqStaticSecret::LEN]> {
        let mut secret_bytes = Zeroizing::new([0u8; PqStaticSecret::LEN]);

        secret_bytes[..KEM_SEED_LEN].copy_from_slice(&*self.secret.kem_seed);
        secret_bytes[KEM_SEED_LEN..].copy_from_slice(&*self.secret.seec_key);

        secret_bytes
    }
}

/// Hybrid X25519 + ML-KEM static secret with an independent SEEC key.
pub struct HybridStaticSecret {
    /// X25519 static secret used by the classical IK tokens.
    pub(crate) dh: StaticSecret,

    /// Seed used to reconstruct the ML-KEM decapsulation key.
    pub(crate) kem_seed: Zeroizing<[u8; KEM_SEED_LEN]>,

    /// Independent persistent key used to harden session randomness.
    pub(crate) seec_key: Zeroizing<[u8; SEEC_KEY_LEN]>,
}

impl HybridStaticSecret {
    /// Serialized length of `x25519_secret || ml_kem_seed || seec_key`.
    pub const LEN: usize = StaticSecret::LEN + KEM_SEED_LEN + SEEC_KEY_LEN;
}

/// Hybrid X25519 + ML-KEM public key.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct HybridPublicKey {
    /// X25519 public key used by the classical IK tokens.
    pub(crate) dh: PublicKey,

    /// ML-KEM-768 encapsulation key used by the pqIK tokens.
    pub(crate) kem_ek: EncapsulationKey,
}

impl HybridPublicKey {
    /// Serialized length of `x25519_public || ml_kem_encapsulation_key`.
    pub const LEN: usize = PublicKey::LEN + EncapsulationKey::LEN;

    /// Borrow the X25519 component of this hybrid public key.
    pub fn dh_public(&self) -> &PublicKey {
        &self.dh
    }

    /// Borrow the ML-KEM component of this hybrid public key.
    pub fn kem_ek(&self) -> &EncapsulationKey {
        &self.kem_ek
    }

    /// Parse `x25519_public || ml_kem_encapsulation_key`.
    pub fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        let mut dh_public = [0u8; PublicKey::LEN];
        dh_public.copy_from_slice(&bytes[..PublicKey::LEN]);

        let mut kem_public = [0u8; EncapsulationKey::LEN];
        kem_public.copy_from_slice(&bytes[PublicKey::LEN..]);

        Self {
            dh: PublicKey::from_bytes(dh_public),
            kem_ek: EncapsulationKey::from_bytes(kem_public),
        }
    }

    /// Serialize `x25519_public || ml_kem_encapsulation_key`.
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut public_bytes = [0u8; Self::LEN];

        public_bytes[..PublicKey::LEN].copy_from_slice(self.dh.as_bytes());
        public_bytes[PublicKey::LEN..].copy_from_slice(self.kem_ek.as_bytes());

        public_bytes
    }
}

/// Hybrid X25519 + ML-KEM static keypair.
pub struct HybridKeyPair {
    /// X25519 secret, ML-KEM seed, and persistent SEEC key.
    pub secret: HybridStaticSecret,

    /// Corresponding X25519 and ML-KEM public keys.
    pub public: HybridPublicKey,
}

impl HybridKeyPair {
    /// Generate independent X25519, ML-KEM, and persistent SEEC key material.
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let dh_keypair = KeyPair::generate(rng);
        let (kem_seed, kem_ek) = kem_generate(rng);

        let mut seec_key = Zeroizing::new([0u8; SEEC_KEY_LEN]);
        rng.fill_bytes(&mut *seec_key);

        Self {
            secret: HybridStaticSecret {
                dh: dh_keypair.secret,
                kem_seed,
                seec_key,
            },

            public: HybridPublicKey {
                dh: dh_keypair.public,
                kem_ek: EncapsulationKey::from_bytes(kem_ek),
            },
        }
    }

    /// Reconstruct both public-key components from an existing hybrid secret.
    pub fn from_secret(secret: HybridStaticSecret) -> Self {
        let dh_keypair = KeyPair::from_secret(secret.dh);
        let kem_ek = kem_ek_from_seed(&secret.kem_seed);

        Self {
            secret: HybridStaticSecret {
                dh: dh_keypair.secret,
                kem_seed: secret.kem_seed,
                seec_key: secret.seec_key,
            },

            public: HybridPublicKey {
                dh: dh_keypair.public,
                kem_ek: EncapsulationKey::from_bytes(kem_ek),
            },
        }
    }

    /// Restore a keypair from `x25519_secret || ml_kem_seed || seec_key`.
    pub fn from_secret_bytes(bytes: &[u8; HybridStaticSecret::LEN]) -> Self {
        let kem_offset = StaticSecret::LEN;
        let seec_offset = kem_offset + KEM_SEED_LEN;

        let mut dh_secret = Zeroizing::new([0u8; StaticSecret::LEN]);
        dh_secret.copy_from_slice(&bytes[..kem_offset]);

        let mut kem_seed = Zeroizing::new([0u8; KEM_SEED_LEN]);
        kem_seed.copy_from_slice(&bytes[kem_offset..seec_offset]);

        let mut seec_key = Zeroizing::new([0u8; SEEC_KEY_LEN]);
        seec_key.copy_from_slice(&bytes[seec_offset..]);

        Self::from_secret(HybridStaticSecret {
            dh: StaticSecret::from_bytes(&dh_secret),
            kem_seed,
            seec_key,
        })
    }

    /// Export `x25519_secret || ml_kem_seed || seec_key` in zeroizing storage.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; HybridStaticSecret::LEN]> {
        let kem_offset = StaticSecret::LEN;
        let seec_offset = kem_offset + KEM_SEED_LEN;
        let mut secret_bytes = Zeroizing::new([0u8; HybridStaticSecret::LEN]);

        secret_bytes[..kem_offset].copy_from_slice(&*self.secret.dh.to_bytes());
        secret_bytes[kem_offset..seec_offset].copy_from_slice(&*self.secret.kem_seed);
        secret_bytes[seec_offset..].copy_from_slice(&*self.secret.seec_key);

        secret_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pq_secret_and_public_round_trip() {
        let keypair = PqKeyPair::generate(&mut rand_core::OsRng);
        let restored = PqKeyPair::from_secret_bytes(&keypair.secret_bytes());

        assert_eq!(keypair.public, restored.public);
        assert_eq!(PqStaticSecret::LEN, 96);
        assert_eq!(PqPublicKey::LEN, 1184);
    }

    #[test]
    fn hybrid_secret_and_public_round_trip() {
        let keypair = HybridKeyPair::generate(&mut rand_core::OsRng);
        let restored = HybridKeyPair::from_secret_bytes(&keypair.secret_bytes());

        assert_eq!(keypair.public, restored.public);
        assert_eq!(HybridStaticSecret::LEN, 128);
        assert_eq!(HybridPublicKey::LEN, 1216);
    }

    #[test]
    fn public_serialization_round_trips() {
        let pq = PqKeyPair::generate(&mut rand_core::OsRng);
        assert_eq!(PqPublicKey::from_bytes(pq.public.to_bytes()), pq.public);

        let hybrid = HybridKeyPair::generate(&mut rand_core::OsRng);
        assert_eq!(
            HybridPublicKey::from_bytes(hybrid.public.to_bytes()),
            hybrid.public,
        );
    }
}
