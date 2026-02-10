//! Interoperability and integration tests for reishi-handshake.
//!
//! Tests the `Noise_IK_25519_ChaChaPoly_BLAKE2s` implementation against
//! the `snow` crate, and verifies internal consistency of the reishi API.

use rand::RngCore;
use reishi_handshake::{
    Error, Handshake, HandshakeAction, KeyPair, PublicKey, StaticSecret, TransportState,
};

const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate random 32-byte private key material.
fn random_private_key() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Build a reishi `KeyPair` from raw 32-byte private key bytes.
fn reishi_keypair_from_bytes(private: &[u8; 32]) -> KeyPair {
    KeyPair::from_secret(StaticSecret::from_bytes(*private))
}

/// Derive the public key from a private key using x25519-dalek directly.
///
/// Both reishi and snow use x25519-dalek under the hood, so the derived
/// public keys are identical.
fn snow_public_key_for(private: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey as DalekPub, StaticSecret as DalekSecret};
    let secret = DalekSecret::from(*private);
    let public = DalekPub::from(&secret);
    public.to_bytes()
}

/// Build a snow initiator from raw key material.
/// `local_priv`: the initiator's private key bytes
/// `remote_pub`: the responder's public key bytes (as snow will use them)
fn build_snow_initiator(local_priv: &[u8; 32], remote_pub: &[u8; 32]) -> snow::HandshakeState {
    snow::Builder::new(PATTERN.parse().unwrap())
        .local_private_key(local_priv)
        .unwrap()
        .remote_public_key(remote_pub)
        .unwrap()
        .build_initiator()
        .unwrap()
}

/// Build a snow responder from raw key material.
fn build_snow_responder(local_priv: &[u8; 32]) -> snow::HandshakeState {
    snow::Builder::new(PATTERN.parse().unwrap())
        .local_private_key(local_priv)
        .unwrap()
        .build_responder()
        .unwrap()
}

/// Drive a full reishi <-> reishi handshake with optional payloads.
/// Returns (initiator_transport, responder_transport).
fn reishi_handshake_pair(
    initiator_kp: &KeyPair,
    responder_kp: &KeyPair,
    prologue: &[u8],
    msg1_payload: &[u8],
    msg2_payload: &[u8],
) -> (TransportState, TransportState) {
    let mut initiator =
        Handshake::new_initiator(initiator_kp, &responder_kp.public, prologue).unwrap();
    let mut responder = Handshake::new_responder(responder_kp, prologue).unwrap();

    // Message 1: initiator -> responder
    assert_eq!(initiator.next_action(), HandshakeAction::WriteMessage);
    let mut buf = vec![0u8; 65535];
    let len = initiator.write_message(msg1_payload, &mut buf).unwrap();

    assert_eq!(responder.next_action(), HandshakeAction::ReadMessage);
    let mut payload_buf = vec![0u8; 65535];
    let plen = responder
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(&payload_buf[..plen], msg1_payload);

    // Message 2: responder -> initiator
    assert_eq!(responder.next_action(), HandshakeAction::WriteMessage);
    let len = responder.write_message(msg2_payload, &mut buf).unwrap();

    assert_eq!(initiator.next_action(), HandshakeAction::ReadMessage);
    let plen = initiator
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(&payload_buf[..plen], msg2_payload);

    // Both complete
    assert_eq!(initiator.next_action(), HandshakeAction::Complete);
    assert_eq!(responder.next_action(), HandshakeAction::Complete);

    let i_transport = initiator.into_transport().unwrap();
    let r_transport = responder.into_transport().unwrap();
    (i_transport, r_transport)
}

// ===========================================================================
// 1. reishi_initiator_snow_responder -- empty payloads
// ===========================================================================

#[test]
fn reishi_initiator_snow_responder() {
    let i_priv = random_private_key();
    let r_priv = random_private_key();

    // Derive public keys consistently
    let r_pub = snow_public_key_for(&r_priv);

    // Build reishi initiator with responder's public key
    let i_kp = reishi_keypair_from_bytes(&i_priv);
    let r_pub_reishi = PublicKey::from_bytes(r_pub);
    let mut initiator = Handshake::new_initiator(&i_kp, &r_pub_reishi, &[]).unwrap();

    // Build snow responder
    let mut responder = build_snow_responder(&r_priv);

    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

    // Msg 1: reishi initiator -> snow responder
    assert_eq!(initiator.next_action(), HandshakeAction::WriteMessage);
    let len = initiator.write_message(&[], &mut buf).unwrap();
    let plen = responder
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(plen, 0);

    // Msg 2: snow responder -> reishi initiator
    let len = responder.write_message(&[], &mut buf).unwrap();
    assert_eq!(initiator.next_action(), HandshakeAction::ReadMessage);
    let plen = initiator
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(plen, 0);

    // Both complete
    assert_eq!(initiator.next_action(), HandshakeAction::Complete);
    assert!(responder.is_handshake_finished());

    // Convert to transport
    let mut i_transport = initiator.into_transport().unwrap();
    let mut r_transport = responder.into_transport_mode().unwrap();

    // Transport: reishi initiator -> snow responder
    let msg = b"hello from reishi initiator";
    let len = i_transport.write_message(msg, &mut buf).unwrap();
    let plen = r_transport
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(&payload_buf[..plen], msg);

    // Transport: snow responder -> reishi initiator
    let msg = b"hello from snow responder";
    let len = r_transport.write_message(msg, &mut buf).unwrap();
    let plen = i_transport
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(&payload_buf[..plen], msg);
}

// ===========================================================================
// 2. snow_initiator_reishi_responder -- empty payloads
// ===========================================================================

#[test]
fn snow_initiator_reishi_responder() {
    let i_priv = random_private_key();
    let r_priv = random_private_key();

    // Build reishi responder and get its public key
    let r_kp = reishi_keypair_from_bytes(&r_priv);
    let r_pub = *r_kp.public.as_bytes();

    // Build snow initiator with responder's reishi-derived public key
    let mut initiator = build_snow_initiator(&i_priv, &r_pub);

    let mut responder = Handshake::new_responder(&r_kp, &[]).unwrap();

    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

    // Msg 1: snow initiator -> reishi responder
    let len = initiator.write_message(&[], &mut buf).unwrap();
    assert_eq!(responder.next_action(), HandshakeAction::ReadMessage);
    let plen = responder
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(plen, 0);

    // Msg 2: reishi responder -> snow initiator
    assert_eq!(responder.next_action(), HandshakeAction::WriteMessage);
    let len = responder.write_message(&[], &mut buf).unwrap();
    let plen = initiator
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(plen, 0);

    // Both complete
    assert_eq!(responder.next_action(), HandshakeAction::Complete);
    assert!(initiator.is_handshake_finished());

    // Convert to transport
    let mut r_transport = responder.into_transport().unwrap();
    let mut i_transport = initiator.into_transport_mode().unwrap();

    // Transport: snow initiator -> reishi responder
    let msg = b"hello from snow initiator";
    let len = i_transport.write_message(msg, &mut buf).unwrap();
    let plen = r_transport
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(&payload_buf[..plen], msg);

    // Transport: reishi responder -> snow initiator
    let msg = b"hello from reishi responder";
    let len = r_transport.write_message(msg, &mut buf).unwrap();
    let plen = i_transport
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(&payload_buf[..plen], msg);
}

// ===========================================================================
// 3. reishi_initiator_snow_responder_with_payload
// ===========================================================================

#[test]
fn reishi_initiator_snow_responder_with_payload() {
    let i_priv = random_private_key();
    let r_priv = random_private_key();

    let r_pub = snow_public_key_for(&r_priv);

    let i_kp = reishi_keypair_from_bytes(&i_priv);
    let r_pub_reishi = PublicKey::from_bytes(r_pub);
    let mut initiator = Handshake::new_initiator(&i_kp, &r_pub_reishi, &[]).unwrap();

    let mut responder = build_snow_responder(&r_priv);

    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

    // Msg 1 with payload
    let msg1_payload = b"initiator handshake payload";
    let len = initiator.write_message(msg1_payload, &mut buf).unwrap();
    let plen = responder
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(&payload_buf[..plen], msg1_payload.as_slice());

    // Msg 2 with payload
    let msg2_payload = b"responder handshake payload";
    let len = responder.write_message(msg2_payload, &mut buf).unwrap();
    let plen = initiator
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(&payload_buf[..plen], msg2_payload.as_slice());

    assert_eq!(initiator.next_action(), HandshakeAction::Complete);
    assert!(responder.is_handshake_finished());
}

// ===========================================================================
// 4. snow_initiator_reishi_responder_with_payload
// ===========================================================================

#[test]
fn snow_initiator_reishi_responder_with_payload() {
    let i_priv = random_private_key();
    let r_priv = random_private_key();

    let r_kp = reishi_keypair_from_bytes(&r_priv);
    let r_pub = *r_kp.public.as_bytes();

    let mut initiator = build_snow_initiator(&i_priv, &r_pub);
    let mut responder = Handshake::new_responder(&r_kp, &[]).unwrap();

    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

    // Msg 1 with payload
    let msg1_payload = b"snow initiator payload msg1";
    let len = initiator.write_message(msg1_payload, &mut buf).unwrap();
    let plen = responder
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(&payload_buf[..plen], msg1_payload.as_slice());

    // Msg 2 with payload
    let msg2_payload = b"reishi responder payload msg2";
    let len = responder.write_message(msg2_payload, &mut buf).unwrap();
    let plen = initiator
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(&payload_buf[..plen], msg2_payload.as_slice());

    assert_eq!(responder.next_action(), HandshakeAction::Complete);
    assert!(initiator.is_handshake_finished());
}

// ===========================================================================
// 5. interop_transport_messages -- multiple transport messages both directions
// ===========================================================================

#[test]
fn interop_transport_messages() {
    let i_priv = random_private_key();
    let r_priv = random_private_key();
    let r_pub = snow_public_key_for(&r_priv);

    // Reishi initiator, snow responder
    let i_kp = reishi_keypair_from_bytes(&i_priv);
    let r_pub_reishi = PublicKey::from_bytes(r_pub);
    let mut initiator = Handshake::new_initiator(&i_kp, &r_pub_reishi, &[]).unwrap();

    let mut responder = build_snow_responder(&r_priv);

    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

    // Complete handshake
    let len = initiator.write_message(&[], &mut buf).unwrap();
    responder
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();

    let len = responder.write_message(&[], &mut buf).unwrap();
    initiator
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();

    let mut i_transport = initiator.into_transport().unwrap();
    let mut r_transport = responder.into_transport_mode().unwrap();

    // Multiple messages in each direction
    for i in 0..10 {
        let msg = format!("initiator message #{}", i);
        let len = i_transport.write_message(msg.as_bytes(), &mut buf).unwrap();
        let plen = r_transport
            .read_message(&buf[..len], &mut payload_buf)
            .unwrap();
        assert_eq!(&payload_buf[..plen], msg.as_bytes());
    }

    for i in 0..10 {
        let msg = format!("responder message #{}", i);
        let len = r_transport.write_message(msg.as_bytes(), &mut buf).unwrap();
        let plen = i_transport
            .read_message(&buf[..len], &mut payload_buf)
            .unwrap();
        assert_eq!(&payload_buf[..plen], msg.as_bytes());
    }

    // Interleaved messages
    for i in 0..5 {
        let msg_i = format!("interleaved-init-{}", i);
        let len = i_transport
            .write_message(msg_i.as_bytes(), &mut buf)
            .unwrap();
        let plen = r_transport
            .read_message(&buf[..len], &mut payload_buf)
            .unwrap();
        assert_eq!(&payload_buf[..plen], msg_i.as_bytes());

        let msg_r = format!("interleaved-resp-{}", i);
        let len = r_transport
            .write_message(msg_r.as_bytes(), &mut buf)
            .unwrap();
        let plen = i_transport
            .read_message(&buf[..len], &mut payload_buf)
            .unwrap();
        assert_eq!(&payload_buf[..plen], msg_r.as_bytes());
    }
}

// ===========================================================================
// 6. reishi_round_trip_empty -- pure reishi, empty payloads
// ===========================================================================

#[test]
fn reishi_round_trip_empty() {
    let mut rng = rand::thread_rng();
    let i_kp = KeyPair::generate(&mut rng);
    let r_kp = KeyPair::generate(&mut rng);

    let (i_transport, r_transport) = reishi_handshake_pair(&i_kp, &r_kp, &[], &[], &[]);

    // Verify both got valid transport states (non-panicking)
    let _ = i_transport.handshake_hash();
    let _ = r_transport.handshake_hash();
}

// ===========================================================================
// 7. reishi_round_trip_with_payload -- pure reishi, with payloads
// ===========================================================================

#[test]
fn reishi_round_trip_with_payload() {
    let mut rng = rand::thread_rng();
    let i_kp = KeyPair::generate(&mut rng);
    let r_kp = KeyPair::generate(&mut rng);

    let msg1_payload = b"hello from initiator during handshake";
    let msg2_payload = b"hello from responder during handshake";

    let (_i_transport, _r_transport) =
        reishi_handshake_pair(&i_kp, &r_kp, &[], msg1_payload, msg2_payload);
}

// ===========================================================================
// 8. reishi_transport_bidirectional -- transport messages in both directions
// ===========================================================================

#[test]
fn reishi_transport_bidirectional() {
    let mut rng = rand::thread_rng();
    let i_kp = KeyPair::generate(&mut rng);
    let r_kp = KeyPair::generate(&mut rng);

    let (mut i_transport, mut r_transport) = reishi_handshake_pair(&i_kp, &r_kp, &[], &[], &[]);

    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

    // Initiator -> Responder
    let msg = b"from initiator";
    let len = i_transport.write_message(msg, &mut buf).unwrap();
    let plen = r_transport
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(&payload_buf[..plen], msg.as_slice());

    // Responder -> Initiator
    let msg = b"from responder";
    let len = r_transport.write_message(msg, &mut buf).unwrap();
    let plen = i_transport
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(&payload_buf[..plen], msg.as_slice());

    // Multiple rounds
    for i in 0..20 {
        let msg_i = format!("init-to-resp-{}", i);
        let len = i_transport
            .write_message(msg_i.as_bytes(), &mut buf)
            .unwrap();
        let plen = r_transport
            .read_message(&buf[..len], &mut payload_buf)
            .unwrap();
        assert_eq!(&payload_buf[..plen], msg_i.as_bytes());

        let msg_r = format!("resp-to-init-{}", i);
        let len = r_transport
            .write_message(msg_r.as_bytes(), &mut buf)
            .unwrap();
        let plen = i_transport
            .read_message(&buf[..len], &mut payload_buf)
            .unwrap();
        assert_eq!(&payload_buf[..plen], msg_r.as_bytes());
    }

    // Empty payload transport message
    let len = i_transport.write_message(&[], &mut buf).unwrap();
    let plen = r_transport
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(plen, 0);
}

// ===========================================================================
// 9. reishi_transport_rekey -- rekey on both sides
// ===========================================================================

#[test]
fn reishi_transport_rekey() {
    let mut rng = rand::thread_rng();
    let i_kp = KeyPair::generate(&mut rng);
    let r_kp = KeyPair::generate(&mut rng);

    let (mut i_transport, mut r_transport) = reishi_handshake_pair(&i_kp, &r_kp, &[], &[], &[]);

    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

    // Send a message before rekeying
    let msg = b"before rekey";
    let len = i_transport.write_message(msg, &mut buf).unwrap();
    let plen = r_transport
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(&payload_buf[..plen], msg.as_slice());

    // Rekey initiator's send and responder's recv (they must match)
    i_transport.rekey_send().unwrap();
    r_transport.rekey_recv().unwrap();

    // Message after rekeying initiator->responder direction
    let msg = b"after rekey initiator->responder";
    let len = i_transport.write_message(msg, &mut buf).unwrap();
    let plen = r_transport
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(&payload_buf[..plen], msg.as_slice());

    // Message in the other direction should still work (not rekeyed yet)
    let msg = b"before rekey responder->initiator";
    let len = r_transport.write_message(msg, &mut buf).unwrap();
    let plen = i_transport
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(&payload_buf[..plen], msg.as_slice());

    // Rekey responder's send and initiator's recv
    r_transport.rekey_send().unwrap();
    i_transport.rekey_recv().unwrap();

    // Message after rekeying responder->initiator direction
    let msg = b"after rekey responder->initiator";
    let len = r_transport.write_message(msg, &mut buf).unwrap();
    let plen = i_transport
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(&payload_buf[..plen], msg.as_slice());

    // Both directions still work after double rekey
    i_transport.rekey_send().unwrap();
    r_transport.rekey_recv().unwrap();

    let msg = b"after double rekey";
    let len = i_transport.write_message(msg, &mut buf).unwrap();
    let plen = r_transport
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(&payload_buf[..plen], msg.as_slice());

    // Verify that mismatched rekey breaks decryption
    i_transport.rekey_send().unwrap();
    // Intentionally NOT rekeying r_transport.rekey_recv()

    let msg = b"this should fail";
    let len = i_transport.write_message(msg, &mut buf).unwrap();
    let result = r_transport.read_message(&buf[..len], &mut payload_buf);
    assert!(
        result.is_err(),
        "Mismatched rekey should cause decryption failure"
    );
}

// ===========================================================================
// 10. handshake_hash_matches -- both sides have the same handshake hash
// ===========================================================================

#[test]
fn handshake_hash_matches() {
    let mut rng = rand::thread_rng();
    let i_kp = KeyPair::generate(&mut rng);
    let r_kp = KeyPair::generate(&mut rng);

    let mut initiator = Handshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();
    let mut responder = Handshake::new_responder(&r_kp, &[]).unwrap();

    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

    // Msg 1
    let len = initiator.write_message(&[], &mut buf).unwrap();
    responder
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();

    // Msg 2
    let len = responder.write_message(&[], &mut buf).unwrap();
    initiator
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();

    // Check handshake hash before into_transport
    let i_hash = *initiator.handshake_hash().unwrap();
    let r_hash = *responder.handshake_hash().unwrap();
    assert_eq!(
        i_hash, r_hash,
        "Handshake hashes must match after handshake completion"
    );

    // Also check via transport state
    let i_transport = initiator.into_transport().unwrap();
    let r_transport = responder.into_transport().unwrap();
    assert_eq!(
        i_transport.handshake_hash(),
        r_transport.handshake_hash(),
        "Transport handshake hashes must match"
    );
    assert_eq!(
        *i_transport.handshake_hash(),
        i_hash,
        "Transport hash must equal pre-transport hash"
    );
}

// ===========================================================================
// 11. prologue_mismatch_fails -- different prologues cause handshake failure
// ===========================================================================

#[test]
fn prologue_mismatch_fails() {
    let mut rng = rand::thread_rng();
    let i_kp = KeyPair::generate(&mut rng);
    let r_kp = KeyPair::generate(&mut rng);

    let mut initiator = Handshake::new_initiator(&i_kp, &r_kp.public, b"prologue-A").unwrap();
    let mut responder = Handshake::new_responder(&r_kp, b"prologue-B").unwrap();

    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

    // Msg 1: initiator -> responder
    // The first message will be written fine; the responder reads it.
    // With IK, the static key is encrypted under a key derived from DH(e, rs).
    // The prologue is mixed into `h` only, and the AEAD uses `h` as AD.
    // So the first encrypted payload (or encrypted static key) will fail decryption
    // because the responder's `h` differs.
    let len = initiator.write_message(&[], &mut buf).unwrap();
    let result = responder.read_message(&buf[..len], &mut payload_buf);
    assert!(
        result.is_err(),
        "Mismatched prologue should cause handshake decryption failure"
    );
}

// ===========================================================================
// 12. wrong_server_key_fails -- initiator uses wrong remote public key
// ===========================================================================

#[test]
fn wrong_server_key_fails() {
    let mut rng = rand::thread_rng();
    let i_kp = KeyPair::generate(&mut rng);
    let r_kp = KeyPair::generate(&mut rng);
    let wrong_kp = KeyPair::generate(&mut rng);

    // Initiator thinks responder has wrong_kp's public key
    let mut initiator = Handshake::new_initiator(&i_kp, &wrong_kp.public, &[]).unwrap();
    let mut responder = Handshake::new_responder(&r_kp, &[]).unwrap();

    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

    // Msg 1: initiator -> responder
    // The initiator computed DH(e, wrong_rs) and DH(s, wrong_rs), but the
    // responder will compute DH(s_resp, re) using its own static key.
    // The keys won't match, so the AEAD decryption of the static key will fail.
    let len = initiator.write_message(&[], &mut buf).unwrap();
    let result = responder.read_message(&buf[..len], &mut payload_buf);
    assert!(
        result.is_err(),
        "Wrong remote public key should cause handshake failure"
    );
}

// ===========================================================================
// 13. truncated_message_fails -- truncated handshake messages are rejected
// ===========================================================================

#[test]
fn truncated_message_fails() {
    let mut rng = rand::thread_rng();
    let i_kp = KeyPair::generate(&mut rng);
    let r_kp = KeyPair::generate(&mut rng);

    // Test truncated msg1
    {
        let mut initiator = Handshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();

        let mut buf = vec![0u8; 65535];
        let mut payload_buf = vec![0u8; 65535];

        let len = initiator.write_message(&[], &mut buf).unwrap();

        // Try various truncation lengths
        for truncated_len in [0, 1, 16, 31, 32, 48, 64, 80, len - 1] {
            if truncated_len >= len {
                continue;
            }
            let mut fresh_responder = Handshake::new_responder(&r_kp, &[]).unwrap();
            let result = fresh_responder.read_message(&buf[..truncated_len], &mut payload_buf);
            assert!(
                result.is_err(),
                "Truncated msg1 at {} bytes (full={}) should fail",
                truncated_len,
                len
            );
        }
    }

    // Test truncated msg2
    {
        let mut buf = vec![0u8; 65535];
        let mut payload_buf = vec![0u8; 65535];

        // Try truncated msg2 at various lengths
        for truncated_len in [0, 1, 16, 31, 32] {
            // We need a fresh handshake pair for each test because the
            // initiator's state advances on read_message.
            let mut fresh_i = Handshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();
            let mut fresh_r = Handshake::new_responder(&r_kp, &[]).unwrap();

            let l1 = fresh_i.write_message(&[], &mut buf).unwrap();
            fresh_r.read_message(&buf[..l1], &mut payload_buf).unwrap();
            let l2 = fresh_r.write_message(&[], &mut buf).unwrap();

            if truncated_len >= l2 {
                continue;
            }

            let result = fresh_i.read_message(&buf[..truncated_len], &mut payload_buf);
            assert!(
                result.is_err(),
                "Truncated msg2 at {} bytes (full={}) should fail",
                truncated_len,
                l2
            );
        }

        // Also test truncation at len-1
        {
            let mut fresh_i = Handshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();
            let mut fresh_r = Handshake::new_responder(&r_kp, &[]).unwrap();

            let l1 = fresh_i.write_message(&[], &mut buf).unwrap();
            fresh_r.read_message(&buf[..l1], &mut payload_buf).unwrap();
            let l2 = fresh_r.write_message(&[], &mut buf).unwrap();

            let result = fresh_i.read_message(&buf[..l2 - 1], &mut payload_buf);
            assert!(
                result.is_err(),
                "Truncated msg2 at {} bytes (full={}) should fail",
                l2 - 1,
                l2
            );
        }
    }
}

// ===========================================================================
// 14. wrong_state_errors -- calling write when should read, etc.
// ===========================================================================

#[test]
fn wrong_state_errors() {
    let mut rng = rand::thread_rng();
    let i_kp = KeyPair::generate(&mut rng);
    let r_kp = KeyPair::generate(&mut rng);

    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

    // Initiator: first action is WriteMessage, so read should fail
    {
        let mut initiator = Handshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();
        assert_eq!(initiator.next_action(), HandshakeAction::WriteMessage);
        let result = initiator.read_message(&[0u8; 96], &mut payload_buf);
        assert_eq!(result, Err(Error::WrongState));
    }

    // Responder: first action is ReadMessage, so write should fail
    {
        let mut responder = Handshake::new_responder(&r_kp, &[]).unwrap();
        assert_eq!(responder.next_action(), HandshakeAction::ReadMessage);
        let result = responder.write_message(&[], &mut buf);
        assert_eq!(result, Err(Error::WrongState));
    }

    // After msg1, initiator should read (not write)
    {
        let mut initiator = Handshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();
        initiator.write_message(&[], &mut buf).unwrap();
        assert_eq!(initiator.next_action(), HandshakeAction::ReadMessage);
        let result = initiator.write_message(&[], &mut buf);
        assert_eq!(result, Err(Error::WrongState));
    }

    // After msg1, responder should write (not read)
    {
        let mut initiator = Handshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();
        let mut responder = Handshake::new_responder(&r_kp, &[]).unwrap();

        let len = initiator.write_message(&[], &mut buf).unwrap();
        responder
            .read_message(&buf[..len], &mut payload_buf)
            .unwrap();
        assert_eq!(responder.next_action(), HandshakeAction::WriteMessage);
        let result = responder.read_message(&[0u8; 48], &mut payload_buf);
        assert_eq!(result, Err(Error::WrongState));
    }

    // After handshake complete, both write and read should fail
    {
        let mut initiator = Handshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();
        let mut responder = Handshake::new_responder(&r_kp, &[]).unwrap();

        let len = initiator.write_message(&[], &mut buf).unwrap();
        responder
            .read_message(&buf[..len], &mut payload_buf)
            .unwrap();
        let len = responder.write_message(&[], &mut buf).unwrap();
        initiator
            .read_message(&buf[..len], &mut payload_buf)
            .unwrap();

        assert_eq!(initiator.next_action(), HandshakeAction::Complete);
        assert_eq!(
            initiator.write_message(&[], &mut buf),
            Err(Error::WrongState)
        );
        assert_eq!(
            initiator.read_message(&[0u8; 48], &mut payload_buf),
            Err(Error::WrongState)
        );

        assert_eq!(responder.next_action(), HandshakeAction::Complete);
        assert_eq!(
            responder.write_message(&[], &mut buf),
            Err(Error::WrongState)
        );
        assert_eq!(
            responder.read_message(&[0u8; 48], &mut payload_buf),
            Err(Error::WrongState)
        );
    }
}

// ===========================================================================
// 15. ask_before_complete_fails -- get_ask before handshake complete
// ===========================================================================

#[test]
fn ask_before_complete_fails() {
    let mut rng = rand::thread_rng();
    let i_kp = KeyPair::generate(&mut rng);
    let r_kp = KeyPair::generate(&mut rng);

    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

    // Before any messages
    {
        let initiator = Handshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();
        assert_eq!(initiator.get_ask(b"test-label"), Err(Error::WrongState));
    }

    {
        let responder = Handshake::new_responder(&r_kp, &[]).unwrap();
        assert_eq!(responder.get_ask(b"test-label"), Err(Error::WrongState));
    }

    // After msg1, before msg2
    {
        let mut initiator = Handshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();
        let mut responder = Handshake::new_responder(&r_kp, &[]).unwrap();

        let len = initiator.write_message(&[], &mut buf).unwrap();
        responder
            .read_message(&buf[..len], &mut payload_buf)
            .unwrap();

        assert_eq!(initiator.get_ask(b"test-label"), Err(Error::WrongState));
        assert_eq!(responder.get_ask(b"test-label"), Err(Error::WrongState));
    }

    // After complete, get_ask should succeed and both sides should agree
    {
        let mut initiator = Handshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();
        let mut responder = Handshake::new_responder(&r_kp, &[]).unwrap();

        let len = initiator.write_message(&[], &mut buf).unwrap();
        responder
            .read_message(&buf[..len], &mut payload_buf)
            .unwrap();
        let len = responder.write_message(&[], &mut buf).unwrap();
        initiator
            .read_message(&buf[..len], &mut payload_buf)
            .unwrap();

        let i_ask = initiator.get_ask(b"test-label").unwrap();
        let r_ask = responder.get_ask(b"test-label").unwrap();
        assert_eq!(i_ask, r_ask, "ASK values must match for both sides");

        // Different labels should produce different ASK values
        let i_ask2 = initiator.get_ask(b"other-label").unwrap();
        assert_ne!(
            i_ask, i_ask2,
            "Different labels must produce different ASK values"
        );
    }
}
