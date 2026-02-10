//! Integration tests for the hybrid PQ Noise IK handshake.
//!
//! Tests `Noise_IKpq_25519+MLKEM768_ChaChaPoly_BLAKE2s` for correctness,
//! state machine safety, and transport interoperability.

#![cfg(feature = "pq")]

use rand_core::OsRng;
use reishi_handshake::{Error, HandshakeAction, PqHandshake, PqKeyPair, TransportState};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Drive a full PQ handshake with optional payloads.
/// Returns (initiator_transport, responder_transport).
fn pq_handshake_pair(
    initiator_kp: &PqKeyPair,
    responder_kp: &PqKeyPair,
    prologue: &[u8],
    msg1_payload: &[u8],
    msg2_payload: &[u8],
) -> (TransportState, TransportState) {
    let mut initiator =
        PqHandshake::new_initiator(initiator_kp, &responder_kp.public, prologue).unwrap();
    let mut responder = PqHandshake::new_responder(responder_kp, prologue).unwrap();

    // PQ msg1 can be ~4640+ bytes, msg2 ~3408+ bytes
    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

    // Message 1: initiator -> responder
    assert_eq!(initiator.next_action(), HandshakeAction::WriteMessage);
    let len = initiator.write_message(msg1_payload, &mut buf).unwrap();

    assert_eq!(responder.next_action(), HandshakeAction::ReadMessage);
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
// 1. PQ round-trip with empty payloads
// ===========================================================================

#[test]
fn pq_round_trip_empty() {
    let i_kp = PqKeyPair::generate(&mut OsRng);
    let r_kp = PqKeyPair::generate(&mut OsRng);

    let (i_transport, r_transport) = pq_handshake_pair(&i_kp, &r_kp, &[], &[], &[]);

    // Both produced valid transport states
    let _ = i_transport.handshake_hash();
    let _ = r_transport.handshake_hash();
}

// ===========================================================================
// 2. PQ round-trip with payloads
// ===========================================================================

#[test]
fn pq_round_trip_with_payloads() {
    let i_kp = PqKeyPair::generate(&mut OsRng);
    let r_kp = PqKeyPair::generate(&mut OsRng);

    let msg1 = b"initiator handshake payload";
    let msg2 = b"responder handshake payload";

    let (_i_transport, _r_transport) = pq_handshake_pair(&i_kp, &r_kp, &[], msg1, msg2);
}

// ===========================================================================
// 3. Transport messages after PQ handshake
// ===========================================================================

#[test]
fn pq_transport_bidirectional() {
    let i_kp = PqKeyPair::generate(&mut OsRng);
    let r_kp = PqKeyPair::generate(&mut OsRng);

    let (mut i_transport, mut r_transport) = pq_handshake_pair(&i_kp, &r_kp, &[], &[], &[]);

    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

    // Initiator -> Responder
    let msg = b"from PQ initiator";
    let len = i_transport.write_message(msg, &mut buf).unwrap();
    let plen = r_transport
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(&payload_buf[..plen], msg.as_slice());

    // Responder -> Initiator
    let msg = b"from PQ responder";
    let len = r_transport.write_message(msg, &mut buf).unwrap();
    let plen = i_transport
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(&payload_buf[..plen], msg.as_slice());

    // Multiple interleaved rounds
    for i in 0..10 {
        let msg_i = format!("pq-init-{}", i);
        let len = i_transport
            .write_message(msg_i.as_bytes(), &mut buf)
            .unwrap();
        let plen = r_transport
            .read_message(&buf[..len], &mut payload_buf)
            .unwrap();
        assert_eq!(&payload_buf[..plen], msg_i.as_bytes());

        let msg_r = format!("pq-resp-{}", i);
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
// 4. Handshake hashes match on both sides
// ===========================================================================

#[test]
fn pq_handshake_hash_matches() {
    let i_kp = PqKeyPair::generate(&mut OsRng);
    let r_kp = PqKeyPair::generate(&mut OsRng);

    let mut initiator = PqHandshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();
    let mut responder = PqHandshake::new_responder(&r_kp, &[]).unwrap();

    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

    let len = initiator.write_message(&[], &mut buf).unwrap();
    responder
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    let len = responder.write_message(&[], &mut buf).unwrap();
    initiator
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();

    let i_hash = *initiator.handshake_hash().unwrap();
    let r_hash = *responder.handshake_hash().unwrap();
    assert_eq!(i_hash, r_hash, "PQ handshake hashes must match");

    let i_transport = initiator.into_transport().unwrap();
    let r_transport = responder.into_transport().unwrap();
    assert_eq!(
        i_transport.handshake_hash(),
        r_transport.handshake_hash(),
        "PQ transport handshake hashes must match"
    );
    assert_eq!(
        *i_transport.handshake_hash(),
        i_hash,
        "Transport hash must equal pre-transport hash"
    );
}

// ===========================================================================
// 5. ASK derivation matches on both sides
// ===========================================================================

#[test]
fn pq_ask_derivation_matches() {
    let i_kp = PqKeyPair::generate(&mut OsRng);
    let r_kp = PqKeyPair::generate(&mut OsRng);

    let mut initiator = PqHandshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();
    let mut responder = PqHandshake::new_responder(&r_kp, &[]).unwrap();

    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

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

    // Different labels produce different ASKs
    let i_ask2 = initiator.get_ask(b"other-label").unwrap();
    assert_ne!(
        i_ask, i_ask2,
        "Different labels must produce different ASK values"
    );
}

#[test]
fn pq_ask_before_complete_fails() {
    let i_kp = PqKeyPair::generate(&mut OsRng);
    let r_kp = PqKeyPair::generate(&mut OsRng);

    let initiator = PqHandshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();
    assert_eq!(initiator.get_ask(b"label"), Err(Error::WrongState));

    let responder = PqHandshake::new_responder(&r_kp, &[]).unwrap();
    assert_eq!(responder.get_ask(b"label"), Err(Error::WrongState));
}

// ===========================================================================
// 6. Prologue mismatch fails
// ===========================================================================

#[test]
fn pq_prologue_mismatch_fails() {
    let i_kp = PqKeyPair::generate(&mut OsRng);
    let r_kp = PqKeyPair::generate(&mut OsRng);

    let mut initiator = PqHandshake::new_initiator(&i_kp, &r_kp.public, b"prologue-A").unwrap();
    let mut responder = PqHandshake::new_responder(&r_kp, b"prologue-B").unwrap();

    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

    let len = initiator.write_message(&[], &mut buf).unwrap();
    let result = responder.read_message(&buf[..len], &mut payload_buf);
    assert!(
        result.is_err(),
        "Mismatched prologue should cause PQ handshake failure"
    );
}

// ===========================================================================
// 7. Wrong remote PQ key fails
// ===========================================================================

#[test]
fn pq_wrong_remote_key_fails() {
    let i_kp = PqKeyPair::generate(&mut OsRng);
    let r_kp = PqKeyPair::generate(&mut OsRng);
    let wrong_kp = PqKeyPair::generate(&mut OsRng);

    // Initiator uses wrong responder key
    let mut initiator = PqHandshake::new_initiator(&i_kp, &wrong_kp.public, &[]).unwrap();
    let mut responder = PqHandshake::new_responder(&r_kp, &[]).unwrap();

    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

    let len = initiator.write_message(&[], &mut buf).unwrap();
    let result = responder.read_message(&buf[..len], &mut payload_buf);
    assert!(
        result.is_err(),
        "Wrong remote PQ key should cause handshake failure"
    );
}

// ===========================================================================
// 8. Truncated messages fail
// ===========================================================================

#[test]
fn pq_truncated_msg1_fails() {
    let i_kp = PqKeyPair::generate(&mut OsRng);
    let r_kp = PqKeyPair::generate(&mut OsRng);

    let mut initiator = PqHandshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();

    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

    let len = initiator.write_message(&[], &mut buf).unwrap();

    for truncated_len in [0, 1, 32, 1216, 2304, 3536, len - 1] {
        if truncated_len >= len {
            continue;
        }
        let mut fresh_responder = PqHandshake::new_responder(&r_kp, &[]).unwrap();
        let result = fresh_responder.read_message(&buf[..truncated_len], &mut payload_buf);
        assert!(
            result.is_err(),
            "Truncated PQ msg1 at {} bytes (full={}) should fail",
            truncated_len,
            len
        );
    }
}

#[test]
fn pq_truncated_msg2_fails() {
    let i_kp = PqKeyPair::generate(&mut OsRng);
    let r_kp = PqKeyPair::generate(&mut OsRng);

    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

    for truncated_len in [0, 1, 32, 1216, 2304, 3392] {
        let mut fresh_i = PqHandshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();
        let mut fresh_r = PqHandshake::new_responder(&r_kp, &[]).unwrap();

        let l1 = fresh_i.write_message(&[], &mut buf).unwrap();
        fresh_r.read_message(&buf[..l1], &mut payload_buf).unwrap();
        let l2 = fresh_r.write_message(&[], &mut buf).unwrap();

        if truncated_len >= l2 {
            continue;
        }

        let result = fresh_i.read_message(&buf[..truncated_len], &mut payload_buf);
        assert!(
            result.is_err(),
            "Truncated PQ msg2 at {} bytes (full={}) should fail",
            truncated_len,
            l2
        );
    }

    // Also truncation at len-1
    {
        let mut fresh_i = PqHandshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();
        let mut fresh_r = PqHandshake::new_responder(&r_kp, &[]).unwrap();

        let l1 = fresh_i.write_message(&[], &mut buf).unwrap();
        fresh_r.read_message(&buf[..l1], &mut payload_buf).unwrap();
        let l2 = fresh_r.write_message(&[], &mut buf).unwrap();

        let result = fresh_i.read_message(&buf[..l2 - 1], &mut payload_buf);
        assert!(
            result.is_err(),
            "Truncated PQ msg2 at {} bytes (full={}) should fail",
            l2 - 1,
            l2
        );
    }
}

// ===========================================================================
// 9. Wrong-state errors
// ===========================================================================

#[test]
fn pq_wrong_state_errors() {
    let i_kp = PqKeyPair::generate(&mut OsRng);
    let r_kp = PqKeyPair::generate(&mut OsRng);

    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

    // Initiator: first action is Write, so read should fail
    {
        let mut initiator = PqHandshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();
        assert_eq!(initiator.next_action(), HandshakeAction::WriteMessage);
        let result = initiator.read_message(&[0u8; 4640], &mut payload_buf);
        assert_eq!(result, Err(Error::WrongState));
    }

    // Responder: first action is Read, so write should fail
    {
        let mut responder = PqHandshake::new_responder(&r_kp, &[]).unwrap();
        assert_eq!(responder.next_action(), HandshakeAction::ReadMessage);
        let result = responder.write_message(&[], &mut buf);
        assert_eq!(result, Err(Error::WrongState));
    }

    // After msg1, initiator should read (not write)
    {
        let mut initiator = PqHandshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();
        initiator.write_message(&[], &mut buf).unwrap();
        assert_eq!(initiator.next_action(), HandshakeAction::ReadMessage);
        let result = initiator.write_message(&[], &mut buf);
        assert_eq!(result, Err(Error::WrongState));
    }

    // After msg1, responder should write (not read)
    {
        let mut initiator = PqHandshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();
        let mut responder = PqHandshake::new_responder(&r_kp, &[]).unwrap();

        let len = initiator.write_message(&[], &mut buf).unwrap();
        responder
            .read_message(&buf[..len], &mut payload_buf)
            .unwrap();
        assert_eq!(responder.next_action(), HandshakeAction::WriteMessage);
        let result = responder.read_message(&[0u8; 3408], &mut payload_buf);
        assert_eq!(result, Err(Error::WrongState));
    }

    // After handshake complete, both write and read should fail
    {
        let mut initiator = PqHandshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();
        let mut responder = PqHandshake::new_responder(&r_kp, &[]).unwrap();

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
            initiator.read_message(&[0u8; 3408], &mut payload_buf),
            Err(Error::WrongState)
        );

        assert_eq!(responder.next_action(), HandshakeAction::Complete);
        assert_eq!(
            responder.write_message(&[], &mut buf),
            Err(Error::WrongState)
        );
        assert_eq!(
            responder.read_message(&[0u8; 4640], &mut payload_buf),
            Err(Error::WrongState)
        );
    }
}

// ===========================================================================
// 10. Message overhead is correct
// ===========================================================================

#[test]
fn pq_message_overhead_correct() {
    let i_kp = PqKeyPair::generate(&mut OsRng);
    let r_kp = PqKeyPair::generate(&mut OsRng);

    let initiator = PqHandshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();
    assert_eq!(initiator.next_message_overhead(), 4640);

    let responder = PqHandshake::new_responder(&r_kp, &[]).unwrap();
    assert_eq!(responder.next_message_overhead(), 0); // responder reads first
}

#[test]
fn pq_msg2_overhead_correct() {
    let i_kp = PqKeyPair::generate(&mut OsRng);
    let r_kp = PqKeyPair::generate(&mut OsRng);

    let mut initiator = PqHandshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();
    let mut responder = PqHandshake::new_responder(&r_kp, &[]).unwrap();

    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

    let len = initiator.write_message(&[], &mut buf).unwrap();
    responder
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();

    assert_eq!(responder.next_message_overhead(), 3408);
}

// ===========================================================================
// 11. Written message sizes match overhead + payload
// ===========================================================================

#[test]
fn pq_message_sizes_match_overhead() {
    let i_kp = PqKeyPair::generate(&mut OsRng);
    let r_kp = PqKeyPair::generate(&mut OsRng);

    let mut initiator = PqHandshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();
    let mut responder = PqHandshake::new_responder(&r_kp, &[]).unwrap();

    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

    // Msg1 with empty payload
    let overhead1 = initiator.next_message_overhead();
    let len1 = initiator.write_message(&[], &mut buf).unwrap();
    assert_eq!(
        len1, overhead1,
        "msg1 with empty payload should equal overhead"
    );

    responder
        .read_message(&buf[..len1], &mut payload_buf)
        .unwrap();

    // Msg2 with empty payload
    let overhead2 = responder.next_message_overhead();
    let len2 = responder.write_message(&[], &mut buf).unwrap();
    assert_eq!(
        len2, overhead2,
        "msg2 with empty payload should equal overhead"
    );

    // Now test with payloads
    let mut initiator2 = PqHandshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();
    let mut responder2 = PqHandshake::new_responder(&r_kp, &[]).unwrap();

    let payload = b"test payload data";
    let overhead1 = initiator2.next_message_overhead();
    let len1 = initiator2.write_message(payload, &mut buf).unwrap();
    assert_eq!(
        len1,
        overhead1 + payload.len(),
        "msg1 size should be overhead + payload"
    );

    responder2
        .read_message(&buf[..len1], &mut payload_buf)
        .unwrap();

    let payload2 = b"response payload";
    let overhead2 = responder2.next_message_overhead();
    let len2 = responder2.write_message(payload2, &mut buf).unwrap();
    assert_eq!(
        len2,
        overhead2 + payload2.len(),
        "msg2 size should be overhead + payload"
    );
}

// ===========================================================================
// 12. Transport rekey after PQ handshake
// ===========================================================================

#[test]
fn pq_transport_rekey() {
    let i_kp = PqKeyPair::generate(&mut OsRng);
    let r_kp = PqKeyPair::generate(&mut OsRng);

    let (mut i_transport, mut r_transport) = pq_handshake_pair(&i_kp, &r_kp, &[], &[], &[]);

    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

    // Send before rekey
    let msg = b"before rekey";
    let len = i_transport.write_message(msg, &mut buf).unwrap();
    let plen = r_transport
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(&payload_buf[..plen], msg.as_slice());

    // Rekey initiator->responder direction
    i_transport.rekey_send().unwrap();
    r_transport.rekey_recv().unwrap();

    let msg = b"after rekey i->r";
    let len = i_transport.write_message(msg, &mut buf).unwrap();
    let plen = r_transport
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(&payload_buf[..plen], msg.as_slice());

    // Other direction still works (not yet rekeyed)
    let msg = b"before rekey r->i";
    let len = r_transport.write_message(msg, &mut buf).unwrap();
    let plen = i_transport
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(&payload_buf[..plen], msg.as_slice());

    // Rekey responder->initiator direction
    r_transport.rekey_send().unwrap();
    i_transport.rekey_recv().unwrap();

    let msg = b"after rekey r->i";
    let len = r_transport.write_message(msg, &mut buf).unwrap();
    let plen = i_transport
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();
    assert_eq!(&payload_buf[..plen], msg.as_slice());

    // Mismatched rekey should fail
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
// 13. Remote public key recovery
// ===========================================================================

#[test]
fn pq_remote_public_key_recovery() {
    let i_kp = PqKeyPair::generate(&mut OsRng);
    let r_kp = PqKeyPair::generate(&mut OsRng);

    let mut initiator = PqHandshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();
    let mut responder = PqHandshake::new_responder(&r_kp, &[]).unwrap();

    // Responder doesn't know initiator's key yet
    assert!(responder.remote_public().is_none());

    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

    let len = initiator.write_message(&[], &mut buf).unwrap();
    responder
        .read_message(&buf[..len], &mut payload_buf)
        .unwrap();

    // Responder now knows the initiator's static hybrid key
    let recovered = responder.remote_public().unwrap();
    assert_eq!(
        recovered.dh_public().as_bytes(),
        i_kp.public.dh_public().as_bytes(),
        "Recovered DH public key must match"
    );
    assert_eq!(
        recovered.kem_ek(),
        i_kp.public.kem_ek(),
        "Recovered KEM encapsulation key must match"
    );
}

// ===========================================================================
// 14. PqPublicKey serialization round-trip
// ===========================================================================

#[test]
fn pq_public_key_serialization() {
    let kp = PqKeyPair::generate(&mut OsRng);

    let bytes = kp.public.to_bytes();
    assert_eq!(bytes.len(), 1216);

    let recovered = reishi_handshake::PqPublicKey::from_bytes(&bytes).unwrap();
    assert_eq!(
        recovered.dh_public().as_bytes(),
        kp.public.dh_public().as_bytes()
    );
    assert_eq!(recovered.kem_ek(), kp.public.kem_ek());

    // Wrong length should fail
    assert!(reishi_handshake::PqPublicKey::from_bytes(&bytes[..1215]).is_none());
    assert!(reishi_handshake::PqPublicKey::from_bytes(&[]).is_none());
}

// ===========================================================================
// 15. Buffer too small for write
// ===========================================================================

#[test]
fn pq_buffer_too_small() {
    let i_kp = PqKeyPair::generate(&mut OsRng);
    let r_kp = PqKeyPair::generate(&mut OsRng);

    let mut initiator = PqHandshake::new_initiator(&i_kp, &r_kp.public, &[]).unwrap();

    let mut small_buf = vec![0u8; 100]; // Way too small for PQ msg1
    let result = initiator.write_message(&[], &mut small_buf);
    assert_eq!(result, Err(Error::BufferTooSmall));
}
