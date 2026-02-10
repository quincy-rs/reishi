use blake2::{Blake2s256, Digest};
use zeroize::Zeroizing;

/// Hash output length (BLAKE2s = 32 bytes).
pub const HASH_LEN: usize = 32;

/// Compute BLAKE2s-256 hash of input.
pub fn hash(input: &[u8]) -> [u8; HASH_LEN] {
    let mut hasher = Blake2s256::new();
    hasher.update(input);
    let result = hasher.finalize();
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&result);
    out
}

/// Compute BLAKE2s-256 hash of two concatenated inputs without allocating.
pub fn hash_two(a: &[u8], b: &[u8]) -> [u8; HASH_LEN] {
    let mut hasher = Blake2s256::new();
    hasher.update(a);
    hasher.update(b);
    let result = hasher.finalize();
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&result);
    out
}

/// Compute HMAC-BLAKE2s per [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104).
///
/// Uses the standard HMAC construction, not BLAKE2's built-in keyed mode,
/// for compatibility with other Noise implementations (notably `snow`).
pub fn hmac(key: &[u8; HASH_LEN], data: &[u8]) -> Zeroizing<[u8; HASH_LEN]> {
    hmac_multi(key, &[data])
}

/// HMAC-BLAKE2s over multiple data slices (fed sequentially to the hasher).
///
/// Avoids concatenating inputs into a temporary buffer.
fn hmac_multi(key: &[u8; HASH_LEN], parts: &[&[u8]]) -> Zeroizing<[u8; HASH_LEN]> {
    const BLOCK_SIZE: usize = 64; // BLAKE2s block size
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    // Key fits within block size (32 <= 64), no pre-hashing needed.
    let mut ipad_key = Zeroizing::new([0u8; BLOCK_SIZE]);
    let mut opad_key = Zeroizing::new([0u8; BLOCK_SIZE]);

    for i in 0..HASH_LEN {
        ipad_key[i] = key[i] ^ IPAD;
        opad_key[i] = key[i] ^ OPAD;
    }
    for i in HASH_LEN..BLOCK_SIZE {
        ipad_key[i] = IPAD;
        opad_key[i] = OPAD;
    }

    let mut inner_hasher = Blake2s256::new();
    inner_hasher.update(ipad_key.as_slice());
    for part in parts {
        inner_hasher.update(part);
    }
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = Blake2s256::new();
    outer_hasher.update(opad_key.as_slice());
    outer_hasher.update(inner_hash);
    let outer_hash = outer_hasher.finalize();

    let mut result = Zeroizing::new([0u8; HASH_LEN]);
    result.copy_from_slice(&outer_hash);
    result
}

/// HKDF with 2 output blocks, per Noise spec Section 5.3.
///
/// Returns `(output1, output2)` where:
/// - `output1 = HMAC(temp_key, 0x01)`
/// - `output2 = HMAC(temp_key, output1 || 0x02)`
pub fn hkdf2(
    chaining_key: &[u8; HASH_LEN],
    input_key_material: &[u8],
) -> (Zeroizing<[u8; HASH_LEN]>, Zeroizing<[u8; HASH_LEN]>) {
    let temp_key = hmac(chaining_key, input_key_material);
    let output1 = hmac(&temp_key, &[0x01]);

    let mut input2 = Zeroizing::new([0u8; HASH_LEN + 1]);
    input2[..HASH_LEN].copy_from_slice(&*output1);
    input2[HASH_LEN] = 0x02;
    let output2 = hmac(&temp_key, input2.as_slice());

    (output1, output2)
}

/// Three zeroized HKDF output blocks.
pub type HkdfOutput3 = (
    Zeroizing<[u8; HASH_LEN]>,
    Zeroizing<[u8; HASH_LEN]>,
    Zeroizing<[u8; HASH_LEN]>,
);

/// HKDF with 3 output blocks, used for ASK (Additional Symmetric Keys) derivation.
pub fn hkdf3(chaining_key: &[u8; HASH_LEN], input_key_material: &[u8]) -> HkdfOutput3 {
    let temp_key = hmac(chaining_key, input_key_material);

    let output1 = hmac(&temp_key, &[0x01]);

    let mut input2 = Zeroizing::new([0u8; HASH_LEN + 1]);
    input2[..HASH_LEN].copy_from_slice(&*output1);
    input2[HASH_LEN] = 0x02;
    let output2 = hmac(&temp_key, input2.as_slice());

    let mut input3 = Zeroizing::new([0u8; HASH_LEN + 1]);
    input3[..HASH_LEN].copy_from_slice(&*output2);
    input3[HASH_LEN] = 0x03;
    let output3 = hmac(&temp_key, input3.as_slice());

    (output1, output2, output3)
}

/// HKDF-Expand per [RFC 5869 Section 2.3](https://datatracker.ietf.org/doc/html/rfc5869#section-2.3).
///
/// Derives `output.len()` bytes from the pseudorandom key `prk` and `info`.
/// Maximum output length is 255 × [`HASH_LEN`] (8160 bytes).
///
/// Returns `true` on success, `false` if the requested length exceeds the maximum.
pub fn hkdf_expand(prk: &[u8; HASH_LEN], info: &[u8], output: &mut [u8]) -> bool {
    if output.is_empty() {
        return true;
    }

    let n = output.len().div_ceil(HASH_LEN);
    if n > 255 {
        return false;
    }

    let mut prev = Zeroizing::new([0u8; HASH_LEN]);
    let mut offset = 0;

    for i in 1..=n {
        // T(i) = HMAC(PRK, T(i-1) || info || i)
        let counter = [i as u8];
        prev = if i > 1 {
            hmac_multi(prk, &[&*prev, info, &counter])
        } else {
            hmac_multi(prk, &[info, &counter])
        };

        let remaining = output.len() - offset;
        let to_copy = remaining.min(HASH_LEN);
        output[offset..offset + to_copy].copy_from_slice(&prev[..to_copy]);
        offset += to_copy;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_deterministic() {
        let h1 = hash(b"hello");
        let h2 = hash(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_different_inputs() {
        let h1 = hash(b"hello");
        let h2 = hash(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hmac_deterministic() {
        let key = [0x42u8; HASH_LEN];
        let h1 = hmac(&key, b"data");
        let h2 = hmac(&key, b"data");
        assert_eq!(*h1, *h2);
    }

    #[test]
    fn hash_two_equals_concatenated_hash() {
        let a = b"hello";
        let b = b"world";
        let mut combined = Vec::new();
        combined.extend_from_slice(a);
        combined.extend_from_slice(b);
        assert_eq!(hash_two(a, b), hash(&combined));
    }

    #[test]
    fn hmac_different_keys() {
        let key1 = [0x01u8; HASH_LEN];
        let key2 = [0x02u8; HASH_LEN];
        let h1 = hmac(&key1, b"data");
        let h2 = hmac(&key2, b"data");
        assert_ne!(*h1, *h2);
    }

    #[test]
    fn hmac_different_data() {
        let key = [0x42u8; HASH_LEN];
        let h1 = hmac(&key, b"data1");
        let h2 = hmac(&key, b"data2");
        assert_ne!(*h1, *h2);
    }

    #[test]
    fn hkdf2_produces_different_outputs() {
        let ck = [0x01u8; HASH_LEN];
        let (o1, o2) = hkdf2(&ck, b"ikm");
        assert_ne!(*o1, *o2);
    }

    #[test]
    fn hkdf3_produces_different_outputs() {
        let ck = [0x01u8; HASH_LEN];
        let (o1, o2, o3) = hkdf3(&ck, b"ikm");
        assert_ne!(*o1, *o2);
        assert_ne!(*o2, *o3);
        assert_ne!(*o1, *o3);
    }

    #[test]
    fn hkdf_expand_single_block() {
        let prk = [0x42u8; HASH_LEN];
        let mut out = [0u8; HASH_LEN];
        assert!(hkdf_expand(&prk, b"info", &mut out));
        // Should equal HMAC(prk, info || 0x01)
        let mut expected_input = Vec::from(b"info".as_slice());
        expected_input.push(0x01);
        assert_eq!(out, *hmac(&prk, &expected_input));
    }

    #[test]
    fn hkdf_expand_multi_block() {
        let prk = [0x42u8; HASH_LEN];
        let mut out = [0u8; HASH_LEN + 16]; // 48 bytes = 2 blocks
        assert!(hkdf_expand(&prk, b"info", &mut out));
        // First 32 bytes should match single-block output
        let mut single = [0u8; HASH_LEN];
        hkdf_expand(&prk, b"info", &mut single);
        assert_eq!(&out[..HASH_LEN], &single);
    }

    #[test]
    fn hkdf_expand_deterministic() {
        let prk = [0x42u8; HASH_LEN];
        let mut out1 = [0u8; 64];
        let mut out2 = [0u8; 64];
        hkdf_expand(&prk, b"info", &mut out1);
        hkdf_expand(&prk, b"info", &mut out2);
        assert_eq!(out1, out2);
    }

    #[test]
    fn hkdf_expand_different_info() {
        let prk = [0x42u8; HASH_LEN];
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        hkdf_expand(&prk, b"info1", &mut out1);
        hkdf_expand(&prk, b"info2", &mut out2);
        assert_ne!(out1, out2);
    }

    #[test]
    fn hkdf_expand_empty_output() {
        let prk = [0u8; HASH_LEN];
        assert!(hkdf_expand(&prk, b"", &mut []));
    }
}
