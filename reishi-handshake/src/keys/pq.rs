//! Hybrid post-quantum key types for the PQ Noise IK handshake.
//!
//! Each type bundles an X25519 (classical) component with an ML-KEM-768
//! (post-quantum) component. This enables the hybrid IK pattern where
//! compromise of either primitive alone does not break the handshake.

use core::hash::{Hash, Hasher};

use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use super::standard::{KeyPair, PublicKey, StaticSecret};
use crate::crypto::pq::{KEM_EK_LEN, KEM_SEED_LEN, kem_ek_from_seed, kem_generate};

/// A hybrid static secret bundling X25519 + ML-KEM-768 keys.
///
/// Both components are zeroized on drop.
pub struct PqStaticSecret {
    /// X25519 static secret.
    pub(crate) dh: StaticSecret,
    /// ML-KEM-768 decapsulation key seed (64 bytes).
    pub(crate) kem_seed: Zeroizing<[u8; KEM_SEED_LEN]>,
}

impl PqStaticSecret {
    /// Total length of a hybrid secret key in bytes (X25519 + ML-KEM-768 seed).
    pub const LEN: usize = StaticSecret::LEN + KEM_SEED_LEN; // 32 + 64 = 96
}

/// An ML-KEM-768 encapsulation key (1184 bytes).
#[derive(Clone)]
pub struct EncapsulationKey([u8; Self::LEN]);

impl EncapsulationKey {
    /// The length of an encapsulation key in bytes.
    pub const LEN: usize = KEM_EK_LEN;

    /// Create from raw 1184-byte encapsulation key.
    pub fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Access the raw bytes of this encapsulation key.
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

/// A hybrid public key bundling X25519 + ML-KEM-768 encapsulation key.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct PqPublicKey {
    /// X25519 public key (32 bytes).
    pub(crate) dh: PublicKey,
    /// ML-KEM-768 encapsulation key (1184 bytes).
    pub(crate) kem_ek: EncapsulationKey,
}

impl PqPublicKey {
    /// Total serialized length: 1216 bytes.
    pub const LEN: usize = PublicKey::LEN + EncapsulationKey::LEN;

    /// Access the X25519 public key component.
    pub fn dh_public(&self) -> &PublicKey {
        &self.dh
    }

    /// Access the ML-KEM-768 encapsulation key.
    pub fn kem_ek(&self) -> &EncapsulationKey {
        &self.kem_ek
    }

    /// Create from raw bytes: `dh_pub(32) || kem_ek(1184)`.
    pub fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        let mut dh_bytes = [0u8; PublicKey::LEN];
        dh_bytes.copy_from_slice(&bytes[..PublicKey::LEN]);
        let mut kem_ek = [0u8; EncapsulationKey::LEN];
        kem_ek.copy_from_slice(&bytes[PublicKey::LEN..]);
        Self {
            dh: PublicKey::from_bytes(dh_bytes),
            kem_ek: EncapsulationKey::from_bytes(kem_ek),
        }
    }

    /// Return the raw bytes: `dh_pub(32) || kem_ek(1184)`.
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[..PublicKey::LEN].copy_from_slice(self.dh.as_bytes());
        out[PublicKey::LEN..].copy_from_slice(self.kem_ek.as_bytes());
        out
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
                kem_ek: EncapsulationKey(kem_ek),
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
                kem_ek: EncapsulationKey(kem_ek),
            },
        }
    }

    /// Create a hybrid keypair from raw secret bytes: `dh_secret(32) || kem_seed(64)`.
    ///
    /// Derives both public key components (X25519 and ML-KEM-768 EK) automatically.
    pub fn from_secret_bytes(bytes: &[u8; PqStaticSecret::LEN]) -> Self {
        let mut dh_bytes = Zeroizing::new([0u8; StaticSecret::LEN]);
        dh_bytes.copy_from_slice(&bytes[..StaticSecret::LEN]);

        let mut kem_seed = Zeroizing::new([0u8; KEM_SEED_LEN]);
        kem_seed.copy_from_slice(&bytes[StaticSecret::LEN..]);

        Self::from_secret(PqStaticSecret {
            dh: StaticSecret::from_bytes(&dh_bytes),
            kem_seed,
        })
    }

    /// Export the raw secret bytes: `dh_secret(32) || kem_seed(64)`.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; PqStaticSecret::LEN]> {
        let mut out = Zeroizing::new([0u8; PqStaticSecret::LEN]);
        out[..StaticSecret::LEN].copy_from_slice(&*self.secret.dh.to_bytes());
        out[StaticSecret::LEN..].copy_from_slice(&*self.secret.kem_seed);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pq::kem_generate;
    use crate::crypto::x25519::DH_LEN;
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
                dh: StaticSecret::from_bytes(&dh_bytes),
                kem_seed: Zeroizing::new(*kem_seed),
            },
            public: PqPublicKey {
                dh: dh_public,
                kem_ek: EncapsulationKey(kem_ek),
            },
        };

        // Reconstruct from the concatenated secret bytes.
        let mut secret_bytes = [0u8; PqStaticSecret::LEN];
        secret_bytes[..DH_LEN].copy_from_slice(&dh_bytes);
        secret_bytes[DH_LEN..].copy_from_slice(&*kem_seed);

        let from_helper = PqKeyPair::from_secret_bytes(&secret_bytes);

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
            dh: StaticSecret::from_bytes(&dh_bytes),
            kem_seed: Zeroizing::new(*kem_seed),
        });

        assert_eq!(*kp.public.dh_public().as_bytes(), expected_dh_public);
        assert_eq!(*kp.public.kem_ek().as_bytes(), kem_ek);
    }

    #[test]
    fn secret_bytes_round_trips() {
        let mut rng = rand_core::OsRng;
        let kp = PqKeyPair::generate(&mut rng);

        let exported = kp.secret_bytes();
        let restored = PqKeyPair::from_secret_bytes(&exported);

        assert_eq!(
            kp.public.dh_public().as_bytes(),
            restored.public.dh_public().as_bytes()
        );
        assert_eq!(kp.public.kem_ek(), restored.public.kem_ek());
    }

    // --- EncapsulationKey tests ---

    #[test]
    fn ek_from_bytes_as_bytes_round_trip() {
        let bytes = [0xab; EncapsulationKey::LEN];
        let ek = EncapsulationKey::from_bytes(bytes);
        assert_eq!(*ek.as_bytes(), bytes);
    }

    #[test]
    fn ek_as_ref_array() {
        let bytes = [7u8; EncapsulationKey::LEN];
        let ek = EncapsulationKey::from_bytes(bytes);
        let r: &[u8; EncapsulationKey::LEN] = ek.as_ref();
        assert_eq!(*r, bytes);
    }

    #[test]
    fn ek_as_ref_slice() {
        let bytes = [7u8; EncapsulationKey::LEN];
        let ek = EncapsulationKey::from_bytes(bytes);
        let r: &[u8] = ek.as_ref();
        assert_eq!(r, &bytes);
    }

    #[test]
    fn ek_equality_constant_time() {
        let a = EncapsulationKey::from_bytes([1u8; EncapsulationKey::LEN]);
        let b = EncapsulationKey::from_bytes([1u8; EncapsulationKey::LEN]);
        let c = EncapsulationKey::from_bytes([2u8; EncapsulationKey::LEN]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn ek_hash_consistent_with_equality() {
        use core::hash::BuildHasher;
        let a = EncapsulationKey::from_bytes([1u8; EncapsulationKey::LEN]);
        let b = EncapsulationKey::from_bytes([1u8; EncapsulationKey::LEN]);

        let s = std::collections::hash_map::RandomState::new();
        let hash = |val: &EncapsulationKey| s.hash_one(val);
        assert_eq!(hash(&a), hash(&b));
    }

    #[test]
    fn ek_debug_does_not_leak_full_key() {
        let ek = EncapsulationKey::from_bytes([0xcd; EncapsulationKey::LEN]);
        let dbg = format!("{:?}", ek);
        assert!(dbg.starts_with("EncapsulationKey("));
        assert!(dbg.contains(&format!("{}B", EncapsulationKey::LEN)));
        // Should only show first 2 bytes, not the full key
        assert!(dbg.len() < 80);
    }

    #[test]
    fn ek_clone_is_equal() {
        let ek = EncapsulationKey::from_bytes([0x42; EncapsulationKey::LEN]);
        let cloned = ek.clone();
        assert_eq!(ek, cloned);
    }

    #[test]
    fn ek_zeroized_on_drop() {
        let bytes = [0xff; EncapsulationKey::LEN];
        let ek = EncapsulationKey::from_bytes(bytes);
        // Manually drop to trigger zeroize
        drop(ek);
        // Can't inspect after drop, but we verify Drop compiles and runs.
        // The real guarantee is the Zeroize impl on the inner array.
    }

    // --- PqPublicKey tests ---

    #[test]
    fn pq_public_key_from_bytes_to_bytes_round_trip() {
        let mut rng = rand_core::OsRng;
        let kp = PqKeyPair::generate(&mut rng);
        let bytes = kp.public.to_bytes();
        let recovered = PqPublicKey::from_bytes(bytes);
        assert_eq!(recovered, kp.public);
    }

    #[test]
    fn pq_public_key_to_bytes_layout() {
        let mut rng = rand_core::OsRng;
        let kp = PqKeyPair::generate(&mut rng);
        let bytes = kp.public.to_bytes();

        assert_eq!(bytes.len(), PqPublicKey::LEN);
        assert_eq!(&bytes[..PublicKey::LEN], kp.public.dh_public().as_bytes());
        assert_eq!(
            &bytes[PublicKey::LEN..],
            kp.public.kem_ek().as_bytes().as_slice()
        );
    }

    #[test]
    fn pq_public_key_equality() {
        let mut rng = rand_core::OsRng;
        let kp1 = PqKeyPair::generate(&mut rng);
        let kp2 = PqKeyPair::generate(&mut rng);
        let clone = kp1.public.clone();
        assert_eq!(kp1.public, clone);
        assert_ne!(kp1.public, kp2.public);
    }
}
