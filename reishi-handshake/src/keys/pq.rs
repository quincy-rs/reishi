//! Hybrid post-quantum key types for the PQ Noise IK handshake.
//!
//! Each type bundles an X25519 (classical) component with an ML-KEM-768
//! (post-quantum) component. This enables the hybrid IK pattern where
//! compromise of either primitive alone does not break the handshake.

use rand_core::CryptoRngCore;
use zeroize::{Zeroize, Zeroizing};

use super::standard::{KeyPair, PublicKey, StaticSecret};
use crate::crypto::pq::{KEM_EK_LEN, KEM_SEED_LEN, kem_ek_from_seed, kem_generate};
use crate::crypto::x25519::DH_LEN;

/// Total length of a hybrid secret key in bytes (X25519 + ML-KEM-768 seed).
pub const HYBRID_SECRET_LEN: usize = DH_LEN + KEM_SEED_LEN; // 32 + 64 = 96

/// Total serialized length of a hybrid public key (X25519 + ML-KEM-768).
pub const HYBRID_PUB_LEN: usize = DH_LEN + KEM_EK_LEN; // 32 + 1184 = 1216

/// A hybrid static secret bundling X25519 + ML-KEM-768 keys.
///
/// Both components are zeroized on drop.
pub struct PqStaticSecret {
    /// X25519 static secret.
    pub(crate) dh: StaticSecret,
    /// ML-KEM-768 decapsulation key seed (64 bytes).
    pub(crate) kem_seed: Zeroizing<[u8; KEM_SEED_LEN]>,
}

/// A hybrid public key bundling X25519 + ML-KEM-768 encapsulation key.
#[derive(Clone)]
pub struct PqPublicKey {
    /// X25519 public key (32 bytes).
    pub(crate) dh: PublicKey,
    /// ML-KEM-768 encapsulation key (1184 bytes).
    pub(crate) kem_ek: [u8; KEM_EK_LEN],
}

impl PqPublicKey {
    /// Total serialized length: 1216 bytes.
    pub const LEN: usize = HYBRID_PUB_LEN;

    /// Access the X25519 public key component.
    pub fn dh_public(&self) -> &PublicKey {
        &self.dh
    }

    /// Access the ML-KEM-768 encapsulation key bytes.
    pub fn kem_ek(&self) -> &[u8; KEM_EK_LEN] {
        &self.kem_ek
    }

    /// Serialize to bytes: `dh_pub(32) || kem_ek(1184)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_PUB_LEN);
        out.extend_from_slice(self.dh.as_bytes());
        out.extend_from_slice(&self.kem_ek);
        out
    }

    /// Deserialize from a byte slice.
    ///
    /// Returns `None` if the slice is not exactly `HYBRID_PUB_LEN` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != HYBRID_PUB_LEN {
            return None;
        }
        let mut dh_bytes = [0u8; DH_LEN];
        dh_bytes.copy_from_slice(&bytes[..DH_LEN]);
        let mut kem_ek = [0u8; KEM_EK_LEN];
        kem_ek.copy_from_slice(&bytes[DH_LEN..]);
        Some(Self {
            dh: PublicKey::from_bytes(dh_bytes),
            kem_ek,
        })
    }
}

impl core::fmt::Debug for PqPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "PqPublicKey(dh={:?}, kem_ek=[{:02x}{:02x}..{}B])",
            self.dh, self.kem_ek[0], self.kem_ek[1], KEM_EK_LEN,
        )
    }
}

impl Drop for PqPublicKey {
    fn drop(&mut self) {
        self.kem_ek.zeroize();
    }
}

/// A hybrid keypair for the PQ Noise IK handshake.
pub struct PqKeyPair {
    pub secret: PqStaticSecret,
    pub public: PqPublicKey,
}

impl PqKeyPair {
    /// Generate a new random hybrid keypair.
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        let dh_kp = KeyPair::generate(rng);
        let (kem_seed, kem_ek) = kem_generate(rng);

        Self {
            secret: PqStaticSecret {
                dh: dh_kp.secret,
                kem_seed,
            },
            public: PqPublicKey {
                dh: dh_kp.public,
                kem_ek,
            },
        }
    }

    /// Create a hybrid keypair from an existing `PqStaticSecret`.
    ///
    /// Derives both public key components (X25519 and ML-KEM-768 EK) automatically.
    pub fn from_secret(secret: PqStaticSecret) -> Self {
        let dh_kp = KeyPair::from_secret(secret.dh);
        let kem_ek = kem_ek_from_seed(&secret.kem_seed);

        Self {
            secret: PqStaticSecret {
                dh: dh_kp.secret,
                kem_seed: secret.kem_seed,
            },
            public: PqPublicKey {
                dh: dh_kp.public,
                kem_ek,
            },
        }
    }

    /// Create a hybrid keypair from raw secret bytes: `dh_secret(32) || kem_seed(64)`.
    ///
    /// Derives both public key components (X25519 and ML-KEM-768 EK) automatically.
    pub fn from_secret_bytes(bytes: [u8; HYBRID_SECRET_LEN]) -> Self {
        let mut dh_bytes = [0u8; DH_LEN];
        dh_bytes.copy_from_slice(&bytes[..DH_LEN]);

        let mut kem_seed = Zeroizing::new([0u8; KEM_SEED_LEN]);
        kem_seed.copy_from_slice(&bytes[DH_LEN..]);

        Self::from_secret(PqStaticSecret {
            dh: StaticSecret::from_bytes(dh_bytes),
            kem_seed,
        })
    }

    /// Export the raw secret bytes: `dh_secret(32) || kem_seed(64)`.
    pub fn secret_bytes(&self) -> [u8; HYBRID_SECRET_LEN] {
        let mut out = [0u8; HYBRID_SECRET_LEN];
        out[..DH_LEN].copy_from_slice(&self.secret.dh.to_bytes());
        out[DH_LEN..].copy_from_slice(&*self.secret.kem_seed);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pq::kem_generate;
    use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret as DalekStaticSecret};

    #[test]
    fn from_secret_bytes_matches_manual_construction() {
        // Build a keypair manually from known components.
        let dh_bytes = [42u8; DH_LEN];
        let dh_secret = DalekStaticSecret::from(dh_bytes);
        let dh_public = PublicKey::from_bytes(DalekPublicKey::from(&dh_secret).to_bytes());

        // Generate a KEM seed and derive its EK the same way kem_generate does.
        let mut rng = rand_core::OsRng;
        let (kem_seed, kem_ek) = kem_generate(&mut rng);

        let manual = PqKeyPair {
            secret: PqStaticSecret {
                dh: StaticSecret::from_bytes(dh_bytes),
                kem_seed: Zeroizing::new(*kem_seed),
            },
            public: PqPublicKey {
                dh: dh_public,
                kem_ek,
            },
        };

        // Reconstruct from the concatenated secret bytes.
        let mut secret_bytes = [0u8; HYBRID_SECRET_LEN];
        secret_bytes[..DH_LEN].copy_from_slice(&dh_bytes);
        secret_bytes[DH_LEN..].copy_from_slice(&*kem_seed);

        let from_helper = PqKeyPair::from_secret_bytes(secret_bytes);

        assert_eq!(
            from_helper.public.dh_public().as_bytes(),
            manual.public.dh_public().as_bytes(),
        );
        assert_eq!(from_helper.public.kem_ek(), manual.public.kem_ek());
    }

    #[test]
    fn from_secret_derives_correct_public_keys() {
        let dh_bytes = [42u8; DH_LEN];
        let mut rng = rand_core::OsRng;
        let (kem_seed, kem_ek) = kem_generate(&mut rng);

        let expected_dh_public =
            DalekPublicKey::from(&DalekStaticSecret::from(dh_bytes)).to_bytes();

        let kp = PqKeyPair::from_secret(PqStaticSecret {
            dh: StaticSecret::from_bytes(dh_bytes),
            kem_seed: Zeroizing::new(*kem_seed),
        });

        assert_eq!(*kp.public.dh_public().as_bytes(), expected_dh_public);
        assert_eq!(*kp.public.kem_ek(), kem_ek);
    }

    #[test]
    fn secret_bytes_round_trips() {
        let mut rng = rand_core::OsRng;
        let kp = PqKeyPair::generate(&mut rng);

        let exported = kp.secret_bytes();
        let restored = PqKeyPair::from_secret_bytes(exported);

        assert_eq!(
            kp.public.dh_public().as_bytes(),
            restored.public.dh_public().as_bytes()
        );
        assert_eq!(kp.public.kem_ek(), restored.public.kem_ek());
    }
}
