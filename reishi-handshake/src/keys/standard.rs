use core::hash::{Hash, Hasher};

use aws_lc_rs::agreement;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::crypto::x25519;
use crate::error::Error;

/// An X25519 static secret key.
///
/// Zeroized from memory when dropped.
#[derive(Clone)]
pub struct StaticSecret(Zeroizing<[u8; Self::LEN]>);

impl StaticSecret {
    /// The length of a static secret key in bytes.
    pub const LEN: usize = 32;

    /// Create from raw 32-byte secret key material.
    pub fn from_bytes(bytes: &[u8; Self::LEN]) -> Self {
        Self(Zeroizing::new(*bytes))
    }

    /// Export the raw 32-byte secret key material.
    pub fn to_bytes(&self) -> Zeroizing<[u8; Self::LEN]> {
        self.0.clone()
    }

    /// Import this secret into aws-lc for DH operations.
    pub(crate) fn private_key(&self) -> Result<agreement::PrivateKey, Error> {
        x25519::private_key(&self.0)
    }
}

/// An X25519 public key (32 bytes).
#[derive(Clone, Copy)]
pub struct PublicKey([u8; Self::LEN]);

impl PublicKey {
    /// The length of a public key in bytes.
    pub const LEN: usize = 32;

    /// Create from raw 32-byte public key.
    pub fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Access the raw bytes of this public key.
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl AsRef<[u8; Self::LEN]> for PublicKey {
    fn as_ref(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for PublicKey {}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PublicKey({:02x?})", &self.0[..4])
    }
}

/// A keypair consisting of a static secret and its corresponding public key.
pub struct KeyPair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl KeyPair {
    /// Generate a new random keypair from aws-lc's CSPRNG.
    pub fn generate() -> Self {
        let mut secret = Zeroizing::new([0u8; StaticSecret::LEN]);
        aws_lc_rs::rand::fill(&mut secret[..]).expect("aws-lc CSPRNG failed");
        Self::from_secret(StaticSecret(secret))
    }

    /// Create a keypair from an existing static secret.
    pub fn from_secret(secret: StaticSecret) -> Self {
        let public = secret
            .private_key()
            .and_then(|key| x25519::public_key(&key))
            .expect("aws-lc derives an X25519 public key for every 32-byte secret");
        Self {
            secret,
            public: PublicKey(public),
        }
    }

    /// Create a keypair from raw 32-byte secret key material.
    ///
    /// Derives the corresponding public key automatically.
    pub fn from_secret_bytes(bytes: &[u8; StaticSecret::LEN]) -> Self {
        Self::from_secret(StaticSecret::from_bytes(bytes))
    }

    /// Export the raw 32-byte secret key material.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; StaticSecret::LEN]> {
        self.secret.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_secret_derives_rfc7748_public_key() {
        // RFC 7748 Section 6.1, Alice.
        let secret: [u8; 32] =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap()
                .try_into()
                .unwrap();
        let public =
            hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
                .unwrap();

        assert_eq!(
            KeyPair::from_secret_bytes(&secret).public.as_bytes()[..],
            public[..]
        );
    }

    #[test]
    fn secret_bytes_round_trips() {
        let bytes = [42u8; 32];
        let kp = KeyPair::from_secret_bytes(&bytes);

        assert_eq!(*kp.secret_bytes(), bytes);
    }

    #[test]
    fn public_key_as_ref_array() {
        let bytes = [7u8; PublicKey::LEN];
        let pk = PublicKey::from_bytes(bytes);
        let r: &[u8; PublicKey::LEN] = pk.as_ref();
        assert_eq!(*r, bytes);
    }

    #[test]
    fn public_key_as_ref_slice() {
        let bytes = [7u8; PublicKey::LEN];
        let pk = PublicKey::from_bytes(bytes);
        let r: &[u8] = pk.as_ref();
        assert_eq!(r, &bytes);
    }

    #[test]
    fn public_key_from_bytes_as_bytes_round_trip() {
        let bytes = [99u8; PublicKey::LEN];
        let pk = PublicKey::from_bytes(bytes);
        assert_eq!(*pk.as_bytes(), bytes);
    }

    #[test]
    fn public_key_equality_constant_time() {
        let a = PublicKey::from_bytes([1u8; PublicKey::LEN]);
        let b = PublicKey::from_bytes([1u8; PublicKey::LEN]);
        let c = PublicKey::from_bytes([2u8; PublicKey::LEN]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn public_key_debug_does_not_leak_full_key() {
        let pk = PublicKey::from_bytes([0xab; PublicKey::LEN]);
        let dbg = format!("{:?}", pk);
        assert!(dbg.starts_with("PublicKey("));
        // Only first 4 bytes shown
        assert!(!dbg.contains(&format!("{:02x?}", &[0xabu8; PublicKey::LEN][..])));
    }
}
