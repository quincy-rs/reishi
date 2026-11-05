#![cfg(feature = "pq")]

use reishi_handshake::{
    Error, HandshakeAction, HybridHandshake, HybridKeyPair, PqHandshake, PqKeyPair,
};

const BUFFER_LEN: usize = 65535;

fn complete_pq_handshake(
    initiator_keypair: &PqKeyPair,
    responder_keypair: &PqKeyPair,
) -> (PqHandshake, PqHandshake) {
    let mut initiator =
        PqHandshake::new_initiator(initiator_keypair, &responder_keypair.public, &[]).unwrap();
    let mut responder = PqHandshake::new_responder(responder_keypair, &[]).unwrap();
    let mut message = vec![0u8; BUFFER_LEN];
    let mut payload = vec![0u8; BUFFER_LEN];

    let message_1_length = initiator.write_message(&[], &mut message).unwrap();
    responder
        .read_message(&message[..message_1_length], &mut payload)
        .unwrap();

    let message_2_length = responder
        .write_message(b"server payload", &mut message)
        .unwrap();
    let server_payload_length = initiator
        .read_message(&message[..message_2_length], &mut payload)
        .unwrap();
    assert_eq!(&payload[..server_payload_length], b"server payload");

    let message_3_length = initiator
        .write_message(b"client payload", &mut message)
        .unwrap();
    let client_payload_length = responder
        .read_message(&message[..message_3_length], &mut payload)
        .unwrap();
    assert_eq!(&payload[..client_payload_length], b"client payload");

    (initiator, responder)
}

fn complete_hybrid_handshake(
    initiator_keypair: &HybridKeyPair,
    responder_keypair: &HybridKeyPair,
) -> (HybridHandshake, HybridHandshake) {
    let mut initiator =
        HybridHandshake::new_initiator(initiator_keypair, &responder_keypair.public, &[]).unwrap();
    let mut responder = HybridHandshake::new_responder(responder_keypair, &[]).unwrap();
    let mut message = vec![0u8; BUFFER_LEN];
    let mut payload = vec![0u8; BUFFER_LEN];

    let message_1_length = initiator.write_message(&[], &mut message).unwrap();
    responder
        .read_message(&message[..message_1_length], &mut payload)
        .unwrap();

    let message_2_length = responder
        .write_message(b"server payload", &mut message)
        .unwrap();
    let server_payload_length = initiator
        .read_message(&message[..message_2_length], &mut payload)
        .unwrap();
    assert_eq!(&payload[..server_payload_length], b"server payload");

    let message_3_length = initiator
        .write_message(b"client payload", &mut message)
        .unwrap();
    let client_payload_length = responder
        .read_message(&message[..message_3_length], &mut payload)
        .unwrap();
    assert_eq!(&payload[..client_payload_length], b"client payload");

    (initiator, responder)
}

#[test]
fn pq_three_flights_authenticate_before_exposing_identity() {
    let initiator_keypair = PqKeyPair::generate();
    let responder_keypair = PqKeyPair::generate();
    let mut initiator =
        PqHandshake::new_initiator(&initiator_keypair, &responder_keypair.public, &[]).unwrap();
    let mut responder = PqHandshake::new_responder(&responder_keypair, &[]).unwrap();
    let mut message = vec![0u8; BUFFER_LEN];
    let mut payload = vec![0u8; BUFFER_LEN];

    assert_eq!(initiator.next_message_overhead(), 3472);
    assert!(!initiator.next_message_accepts_payload());
    assert!(initiator.remote_public().is_none());
    assert_eq!(
        initiator.write_message(b"forbidden", &mut message),
        Err(Error::WrongState),
    );

    let message_1_length = initiator.write_message(&[], &mut message).unwrap();
    assert_eq!(message_1_length, 3472);
    assert_eq!(
        responder
            .read_message(&message[..message_1_length], &mut payload)
            .unwrap(),
        0,
    );
    assert!(responder.remote_public().is_none());
    assert!(!responder.is_remote_authenticated());
    assert_eq!(responder.get_ask(b"test"), Err(Error::WrongState));

    assert_eq!(responder.next_message_overhead(), 2208);
    assert!(responder.next_message_accepts_payload());
    let message_2_length = responder.write_message(b"server", &mut message).unwrap();
    assert_eq!(message_2_length, 2208 + b"server".len());

    let server_payload_length = initiator
        .read_message(&message[..message_2_length], &mut payload)
        .unwrap();
    assert_eq!(&payload[..server_payload_length], b"server");
    assert!(initiator.is_remote_authenticated());
    assert_eq!(initiator.remote_public().unwrap(), responder_keypair.public);
    assert_eq!(initiator.get_ask(b"test"), Err(Error::WrongState));

    assert_eq!(initiator.next_message_overhead(), 16);
    let message_3_length = initiator.write_message(b"client", &mut message).unwrap();
    assert_eq!(message_3_length, 16 + b"client".len());
    assert_eq!(initiator.next_action(), HandshakeAction::Complete);

    let client_payload_length = responder
        .read_message(&message[..message_3_length], &mut payload)
        .unwrap();
    assert_eq!(&payload[..client_payload_length], b"client");
    assert_eq!(responder.next_action(), HandshakeAction::Complete);
    assert_eq!(responder.remote_public().unwrap(), initiator_keypair.public);
}

#[test]
fn hybrid_three_flights_authenticate_before_exposing_identity() {
    let initiator_keypair = HybridKeyPair::generate();
    let responder_keypair = HybridKeyPair::generate();
    let mut initiator =
        HybridHandshake::new_initiator(&initiator_keypair, &responder_keypair.public, &[]).unwrap();
    let mut responder = HybridHandshake::new_responder(&responder_keypair, &[]).unwrap();
    let mut message = vec![0u8; BUFFER_LEN];
    let mut payload = vec![0u8; BUFFER_LEN];

    assert_eq!(initiator.next_message_overhead(), 3536);
    assert!(!initiator.next_message_accepts_payload());
    assert!(initiator.remote_public().is_none());
    assert_eq!(
        initiator.write_message(b"forbidden", &mut message),
        Err(Error::WrongState),
    );

    let message_1_length = initiator.write_message(&[], &mut message).unwrap();
    assert_eq!(message_1_length, 3536);
    assert_eq!(
        responder
            .read_message(&message[..message_1_length], &mut payload)
            .unwrap(),
        0,
    );
    assert!(responder.remote_public().is_none());
    assert!(!responder.is_remote_authenticated());

    assert_eq!(responder.next_message_overhead(), 2240);
    let message_2_length = responder.write_message(b"server", &mut message).unwrap();
    assert_eq!(message_2_length, 2240 + b"server".len());

    let server_payload_length = initiator
        .read_message(&message[..message_2_length], &mut payload)
        .unwrap();
    assert_eq!(&payload[..server_payload_length], b"server");
    assert_eq!(initiator.remote_public().unwrap(), responder_keypair.public);

    assert_eq!(initiator.next_message_overhead(), 16);
    let message_3_length = initiator.write_message(b"client", &mut message).unwrap();
    let client_payload_length = responder
        .read_message(&message[..message_3_length], &mut payload)
        .unwrap();
    assert_eq!(&payload[..client_payload_length], b"client");
    assert_eq!(responder.remote_public().unwrap(), initiator_keypair.public);
}

#[test]
fn pq_transcript_ask_and_transport_match() {
    let initiator_keypair = PqKeyPair::generate();
    let responder_keypair = PqKeyPair::generate();
    let (initiator, responder) = complete_pq_handshake(&initiator_keypair, &responder_keypair);

    assert_eq!(
        initiator.handshake_hash().unwrap(),
        responder.handshake_hash().unwrap(),
    );
    assert_eq!(
        initiator.get_ask(b"label").unwrap(),
        responder.get_ask(b"label").unwrap(),
    );

    let mut initiator_transport = initiator.into_transport().unwrap();
    let mut responder_transport = responder.into_transport().unwrap();
    let mut ciphertext = [0u8; 128];
    let mut plaintext = [0u8; 128];
    let ciphertext_length = initiator_transport
        .write_message(b"transport", &mut ciphertext)
        .unwrap();
    let plaintext_length = responder_transport
        .read_message(&ciphertext[..ciphertext_length], &mut plaintext)
        .unwrap();

    assert_eq!(&plaintext[..plaintext_length], b"transport");
}

#[test]
fn hybrid_transcript_ask_and_transport_match() {
    let initiator_keypair = HybridKeyPair::generate();
    let responder_keypair = HybridKeyPair::generate();
    let (initiator, responder) = complete_hybrid_handshake(&initiator_keypair, &responder_keypair);

    assert_eq!(
        initiator.handshake_hash().unwrap(),
        responder.handshake_hash().unwrap(),
    );
    assert_eq!(
        initiator.get_ask(b"label").unwrap(),
        responder.get_ask(b"label").unwrap(),
    );

    let mut initiator_transport = initiator.into_transport().unwrap();
    let mut responder_transport = responder.into_transport().unwrap();
    let mut ciphertext = [0u8; 128];
    let mut plaintext = [0u8; 128];
    let ciphertext_length = responder_transport
        .write_message(b"transport", &mut ciphertext)
        .unwrap();
    let plaintext_length = initiator_transport
        .read_message(&ciphertext[..ciphertext_length], &mut plaintext)
        .unwrap();

    assert_eq!(&plaintext[..plaintext_length], b"transport");
}

#[test]
fn pq_rejects_truncation_tampering_and_wrong_key() {
    let initiator_keypair = PqKeyPair::generate();
    let responder_keypair = PqKeyPair::generate();
    let wrong_responder = PqKeyPair::generate();
    let mut message = vec![0u8; BUFFER_LEN];
    let mut payload = vec![0u8; BUFFER_LEN];

    let mut wrong_initiator =
        PqHandshake::new_initiator(&initiator_keypair, &wrong_responder.public, &[]).unwrap();
    let mut responder = PqHandshake::new_responder(&responder_keypair, &[]).unwrap();
    let message_length = wrong_initiator.write_message(&[], &mut message).unwrap();
    assert!(
        responder
            .read_message(&message[..message_length], &mut payload)
            .is_err(),
    );

    let mut initiator =
        PqHandshake::new_initiator(&initiator_keypair, &responder_keypair.public, &[]).unwrap();
    let message_length = initiator.write_message(&[], &mut message).unwrap();
    let original_message = message[..message_length].to_vec();

    for truncated_length in [0, 1, 1088, 3471] {
        let mut fresh_responder = PqHandshake::new_responder(&responder_keypair, &[]).unwrap();
        assert!(
            fresh_responder
                .read_message(&original_message[..truncated_length], &mut payload)
                .is_err(),
        );
    }

    let mut tampered_message = original_message;
    tampered_message[1200] ^= 1;
    let mut fresh_responder = PqHandshake::new_responder(&responder_keypair, &[]).unwrap();
    assert!(
        fresh_responder
            .read_message(&tampered_message, &mut payload)
            .is_err(),
    );
}

#[test]
fn hybrid_rejects_truncation_tampering_and_wrong_key() {
    let initiator_keypair = HybridKeyPair::generate();
    let responder_keypair = HybridKeyPair::generate();
    let wrong_responder = HybridKeyPair::generate();
    let mut message = vec![0u8; BUFFER_LEN];
    let mut payload = vec![0u8; BUFFER_LEN];

    let mut wrong_initiator =
        HybridHandshake::new_initiator(&initiator_keypair, &wrong_responder.public, &[]).unwrap();
    let mut responder = HybridHandshake::new_responder(&responder_keypair, &[]).unwrap();
    let message_length = wrong_initiator.write_message(&[], &mut message).unwrap();
    assert!(
        responder
            .read_message(&message[..message_length], &mut payload)
            .is_err(),
    );

    let mut initiator =
        HybridHandshake::new_initiator(&initiator_keypair, &responder_keypair.public, &[]).unwrap();
    let message_length = initiator.write_message(&[], &mut message).unwrap();
    let original_message = message[..message_length].to_vec();

    for truncated_length in [0, 1, 1088, 3535] {
        let mut fresh_responder = HybridHandshake::new_responder(&responder_keypair, &[]).unwrap();
        assert!(
            fresh_responder
                .read_message(&original_message[..truncated_length], &mut payload)
                .is_err(),
        );
    }

    let mut tampered_message = original_message;
    tampered_message[1400] ^= 1;
    let mut fresh_responder = HybridHandshake::new_responder(&responder_keypair, &[]).unwrap();
    assert!(
        fresh_responder
            .read_message(&tampered_message, &mut payload)
            .is_err(),
    );
}

#[test]
fn pq_rejects_truncated_messages_2_and_3() {
    let initiator_keypair = PqKeyPair::generate();
    let responder_keypair = PqKeyPair::generate();
    let mut message = vec![0u8; BUFFER_LEN];
    let mut payload = vec![0u8; BUFFER_LEN];

    let mut initiator =
        PqHandshake::new_initiator(&initiator_keypair, &responder_keypair.public, &[]).unwrap();
    let mut responder = PqHandshake::new_responder(&responder_keypair, &[]).unwrap();

    let message_1_length = initiator.write_message(&[], &mut message).unwrap();
    responder
        .read_message(&message[..message_1_length], &mut payload)
        .unwrap();

    let message_2_length = responder.write_message(&[], &mut message).unwrap();
    assert!(
        initiator
            .read_message(&message[..message_2_length - 1], &mut payload)
            .is_err(),
    );

    let mut initiator =
        PqHandshake::new_initiator(&initiator_keypair, &responder_keypair.public, &[]).unwrap();
    let mut responder = PqHandshake::new_responder(&responder_keypair, &[]).unwrap();

    let message_1_length = initiator.write_message(&[], &mut message).unwrap();
    responder
        .read_message(&message[..message_1_length], &mut payload)
        .unwrap();

    let message_2_length = responder.write_message(&[], &mut message).unwrap();
    initiator
        .read_message(&message[..message_2_length], &mut payload)
        .unwrap();

    let message_3_length = initiator.write_message(&[], &mut message).unwrap();
    assert!(
        responder
            .read_message(&message[..message_3_length - 1], &mut payload)
            .is_err(),
    );
}

#[test]
fn hybrid_rejects_truncated_messages_2_and_3() {
    let initiator_keypair = HybridKeyPair::generate();
    let responder_keypair = HybridKeyPair::generate();
    let mut message = vec![0u8; BUFFER_LEN];
    let mut payload = vec![0u8; BUFFER_LEN];

    let mut initiator =
        HybridHandshake::new_initiator(&initiator_keypair, &responder_keypair.public, &[]).unwrap();
    let mut responder = HybridHandshake::new_responder(&responder_keypair, &[]).unwrap();

    let message_1_length = initiator.write_message(&[], &mut message).unwrap();
    responder
        .read_message(&message[..message_1_length], &mut payload)
        .unwrap();

    let message_2_length = responder.write_message(&[], &mut message).unwrap();
    assert!(
        initiator
            .read_message(&message[..message_2_length - 1], &mut payload)
            .is_err(),
    );

    let mut initiator =
        HybridHandshake::new_initiator(&initiator_keypair, &responder_keypair.public, &[]).unwrap();
    let mut responder = HybridHandshake::new_responder(&responder_keypair, &[]).unwrap();

    let message_1_length = initiator.write_message(&[], &mut message).unwrap();
    responder
        .read_message(&message[..message_1_length], &mut payload)
        .unwrap();

    let message_2_length = responder.write_message(&[], &mut message).unwrap();
    initiator
        .read_message(&message[..message_2_length], &mut payload)
        .unwrap();

    let message_3_length = initiator.write_message(&[], &mut message).unwrap();
    assert!(
        responder
            .read_message(&message[..message_3_length - 1], &mut payload)
            .is_err(),
    );
}

#[test]
fn pq_message_3_tampering_never_authenticates_responder_view() {
    let initiator_keypair = PqKeyPair::generate();
    let responder_keypair = PqKeyPair::generate();
    let mut initiator =
        PqHandshake::new_initiator(&initiator_keypair, &responder_keypair.public, &[]).unwrap();
    let mut responder = PqHandshake::new_responder(&responder_keypair, &[]).unwrap();
    let mut message = vec![0u8; BUFFER_LEN];
    let mut payload = vec![0u8; BUFFER_LEN];

    let message_1_length = initiator.write_message(&[], &mut message).unwrap();
    responder
        .read_message(&message[..message_1_length], &mut payload)
        .unwrap();
    let message_2_length = responder.write_message(&[], &mut message).unwrap();
    initiator
        .read_message(&message[..message_2_length], &mut payload)
        .unwrap();
    let message_3_length = initiator.write_message(&[], &mut message).unwrap();
    message[0] ^= 1;

    assert!(
        responder
            .read_message(&message[..message_3_length], &mut payload)
            .is_err(),
    );
    assert!(!responder.is_remote_authenticated());
    assert!(responder.remote_public().is_none());
    assert_eq!(responder.get_ask(b"label"), Err(Error::WrongState));
}

#[test]
fn hybrid_message_3_tampering_never_authenticates_responder_view() {
    let initiator_keypair = HybridKeyPair::generate();
    let responder_keypair = HybridKeyPair::generate();
    let mut initiator =
        HybridHandshake::new_initiator(&initiator_keypair, &responder_keypair.public, &[]).unwrap();
    let mut responder = HybridHandshake::new_responder(&responder_keypair, &[]).unwrap();
    let mut message = vec![0u8; BUFFER_LEN];
    let mut payload = vec![0u8; BUFFER_LEN];

    let message_1_length = initiator.write_message(&[], &mut message).unwrap();
    responder
        .read_message(&message[..message_1_length], &mut payload)
        .unwrap();
    let message_2_length = responder.write_message(&[], &mut message).unwrap();
    initiator
        .read_message(&message[..message_2_length], &mut payload)
        .unwrap();
    let message_3_length = initiator.write_message(&[], &mut message).unwrap();
    message[0] ^= 1;

    assert!(
        responder
            .read_message(&message[..message_3_length], &mut payload)
            .is_err(),
    );
    assert!(!responder.is_remote_authenticated());
    assert!(responder.remote_public().is_none());
}

#[test]
fn forged_pq_identity_without_victim_secret_fails_confirmation() {
    let attacker = PqKeyPair::generate();
    let victim = PqKeyPair::generate();
    let responder_keypair = PqKeyPair::generate();
    let victim_public = victim.public.clone();
    let forged_keypair = PqKeyPair {
        secret: attacker.secret,
        public: victim_public,
    };
    let mut attacker_handshake =
        PqHandshake::new_initiator(&forged_keypair, &responder_keypair.public, &[]).unwrap();
    let mut responder = PqHandshake::new_responder(&responder_keypair, &[]).unwrap();
    let mut message = vec![0u8; BUFFER_LEN];
    let mut payload = vec![0u8; BUFFER_LEN];

    let message_1_length = attacker_handshake.write_message(&[], &mut message).unwrap();
    responder
        .read_message(&message[..message_1_length], &mut payload)
        .unwrap();
    assert!(responder.remote_public().is_none());

    let message_2_length = responder.write_message(&[], &mut message).unwrap();
    assert!(
        attacker_handshake
            .read_message(&message[..message_2_length], &mut payload)
            .is_err(),
    );
    assert!(responder.read_message(&[0u8; 16], &mut payload).is_err(),);
    assert!(responder.remote_public().is_none());
    assert_eq!(responder.get_ask(b"label"), Err(Error::WrongState));
}

#[test]
fn forged_hybrid_identity_without_victim_secret_fails_confirmation() {
    let attacker = HybridKeyPair::generate();
    let victim = HybridKeyPair::generate();
    let responder_keypair = HybridKeyPair::generate();
    let forged_keypair = HybridKeyPair {
        secret: attacker.secret,
        public: victim.public.clone(),
    };
    let mut attacker_handshake =
        HybridHandshake::new_initiator(&forged_keypair, &responder_keypair.public, &[]).unwrap();
    let mut responder = HybridHandshake::new_responder(&responder_keypair, &[]).unwrap();
    let mut message = vec![0u8; BUFFER_LEN];
    let mut payload = vec![0u8; BUFFER_LEN];

    let message_1_length = attacker_handshake.write_message(&[], &mut message).unwrap();
    responder
        .read_message(&message[..message_1_length], &mut payload)
        .unwrap();
    assert!(responder.remote_public().is_none());

    let message_2_length = responder.write_message(&[], &mut message).unwrap();
    assert!(
        attacker_handshake
            .read_message(&message[..message_2_length], &mut payload)
            .is_err(),
    );
    assert!(responder.read_message(&[0u8; 16], &mut payload).is_err(),);
    assert!(responder.remote_public().is_none());
}

#[test]
fn pq_and_hybrid_writers_enforce_message_limit() {
    const OVERSIZED_BUFFER_LEN: usize = BUFFER_LEN + 1;
    const PQ_MESSAGE_2_OVERHEAD: usize = 2208;
    const HYBRID_MESSAGE_2_OVERHEAD: usize = 2240;
    const MESSAGE_3_OVERHEAD: usize = 16;

    let mut message = vec![0u8; OVERSIZED_BUFFER_LEN];
    let mut payload_output = vec![0u8; BUFFER_LEN];

    let pq_initiator_keypair = PqKeyPair::generate();
    let pq_responder_keypair = PqKeyPair::generate();
    let mut pq_initiator =
        PqHandshake::new_initiator(&pq_initiator_keypair, &pq_responder_keypair.public, &[])
            .unwrap();
    let mut pq_responder = PqHandshake::new_responder(&pq_responder_keypair, &[]).unwrap();

    let message_1_len = pq_initiator.write_message(&[], &mut message).unwrap();
    pq_responder
        .read_message(&message[..message_1_len], &mut payload_output)
        .unwrap();

    let oversized_message_2_payload = vec![0u8; OVERSIZED_BUFFER_LEN - PQ_MESSAGE_2_OVERHEAD];

    assert_eq!(
        pq_responder.write_message(&oversized_message_2_payload, &mut message),
        Err(Error::BadMessage),
    );
    assert_eq!(pq_responder.next_action(), HandshakeAction::WriteMessage);

    let exact_message_2_payload = vec![0u8; BUFFER_LEN - PQ_MESSAGE_2_OVERHEAD];
    let message_2_len = pq_responder
        .write_message(&exact_message_2_payload, &mut message)
        .unwrap();

    assert_eq!(message_2_len, BUFFER_LEN);
    assert_eq!(
        pq_initiator
            .read_message(&message[..message_2_len], &mut payload_output)
            .unwrap(),
        exact_message_2_payload.len(),
    );

    let oversized_message_3_payload = vec![0u8; OVERSIZED_BUFFER_LEN - MESSAGE_3_OVERHEAD];

    assert_eq!(
        pq_initiator.write_message(&oversized_message_3_payload, &mut message),
        Err(Error::BadMessage),
    );
    assert_eq!(pq_initiator.next_action(), HandshakeAction::WriteMessage);

    let exact_message_3_payload = vec![0u8; BUFFER_LEN - MESSAGE_3_OVERHEAD];

    assert_eq!(
        pq_initiator
            .write_message(&exact_message_3_payload, &mut message)
            .unwrap(),
        BUFFER_LEN,
    );

    let hybrid_initiator_keypair = HybridKeyPair::generate();
    let hybrid_responder_keypair = HybridKeyPair::generate();
    let mut hybrid_initiator = HybridHandshake::new_initiator(
        &hybrid_initiator_keypair,
        &hybrid_responder_keypair.public,
        &[],
    )
    .unwrap();
    let mut hybrid_responder =
        HybridHandshake::new_responder(&hybrid_responder_keypair, &[]).unwrap();

    let message_1_len = hybrid_initiator.write_message(&[], &mut message).unwrap();
    hybrid_responder
        .read_message(&message[..message_1_len], &mut payload_output)
        .unwrap();

    let oversized_message_2_payload = vec![0u8; OVERSIZED_BUFFER_LEN - HYBRID_MESSAGE_2_OVERHEAD];

    assert_eq!(
        hybrid_responder.write_message(&oversized_message_2_payload, &mut message),
        Err(Error::BadMessage),
    );
    assert_eq!(
        hybrid_responder.next_action(),
        HandshakeAction::WriteMessage,
    );

    let exact_message_2_payload = vec![0u8; BUFFER_LEN - HYBRID_MESSAGE_2_OVERHEAD];
    let message_2_len = hybrid_responder
        .write_message(&exact_message_2_payload, &mut message)
        .unwrap();

    assert_eq!(message_2_len, BUFFER_LEN);
    assert_eq!(
        hybrid_initiator
            .read_message(&message[..message_2_len], &mut payload_output)
            .unwrap(),
        exact_message_2_payload.len(),
    );

    assert_eq!(
        hybrid_initiator.write_message(&oversized_message_3_payload, &mut message),
        Err(Error::BadMessage),
    );
    assert_eq!(
        hybrid_initiator.next_action(),
        HandshakeAction::WriteMessage,
    );

    assert_eq!(
        hybrid_initiator
            .write_message(&exact_message_3_payload, &mut message)
            .unwrap(),
        BUFFER_LEN,
    );
}

#[test]
fn pq_and_hybrid_payload_buffer_errors_are_retryable() {
    let mut message = vec![0u8; BUFFER_LEN];
    let mut payload_output = vec![0u8; BUFFER_LEN];
    let responder_payload = b"responder payload";

    let pq_initiator_keypair = PqKeyPair::generate();
    let pq_responder_keypair = PqKeyPair::generate();
    let mut pq_initiator =
        PqHandshake::new_initiator(&pq_initiator_keypair, &pq_responder_keypair.public, &[])
            .unwrap();
    let mut pq_responder = PqHandshake::new_responder(&pq_responder_keypair, &[]).unwrap();

    let message_1_length = pq_initiator.write_message(&[], &mut message).unwrap();
    pq_responder
        .read_message(&message[..message_1_length], &mut payload_output)
        .unwrap();

    let message_2_length = pq_responder
        .write_message(responder_payload, &mut message)
        .unwrap();

    assert_eq!(
        pq_initiator.read_message(&message[..message_2_length], &mut []),
        Err(Error::BufferTooSmall),
    );
    assert_eq!(pq_initiator.next_action(), HandshakeAction::ReadMessage);

    let payload_length = pq_initiator
        .read_message(&message[..message_2_length], &mut payload_output)
        .unwrap();
    assert_eq!(&payload_output[..payload_length], responder_payload);

    let message_3_length = pq_initiator.write_message(&[], &mut message).unwrap();
    pq_responder
        .read_message(&message[..message_3_length], &mut payload_output)
        .unwrap();
    assert_eq!(
        pq_initiator.handshake_hash().unwrap(),
        pq_responder.handshake_hash().unwrap(),
    );

    let hybrid_initiator_keypair = HybridKeyPair::generate();
    let hybrid_responder_keypair = HybridKeyPair::generate();
    let mut hybrid_initiator = HybridHandshake::new_initiator(
        &hybrid_initiator_keypair,
        &hybrid_responder_keypair.public,
        &[],
    )
    .unwrap();
    let mut hybrid_responder =
        HybridHandshake::new_responder(&hybrid_responder_keypair, &[]).unwrap();

    let message_1_length = hybrid_initiator.write_message(&[], &mut message).unwrap();
    hybrid_responder
        .read_message(&message[..message_1_length], &mut payload_output)
        .unwrap();

    let message_2_length = hybrid_responder
        .write_message(responder_payload, &mut message)
        .unwrap();

    assert_eq!(
        hybrid_initiator.read_message(&message[..message_2_length], &mut []),
        Err(Error::BufferTooSmall),
    );
    assert_eq!(hybrid_initiator.next_action(), HandshakeAction::ReadMessage,);

    let payload_length = hybrid_initiator
        .read_message(&message[..message_2_length], &mut payload_output)
        .unwrap();
    assert_eq!(&payload_output[..payload_length], responder_payload);

    let message_3_length = hybrid_initiator.write_message(&[], &mut message).unwrap();
    hybrid_responder
        .read_message(&message[..message_3_length], &mut payload_output)
        .unwrap();
    assert_eq!(
        hybrid_initiator.handshake_hash().unwrap(),
        hybrid_responder.handshake_hash().unwrap(),
    );
}

#[test]
fn pq_and_hybrid_reject_cross_suite_message_splices() {
    let pq_initiator_keypair = PqKeyPair::generate();
    let pq_responder_keypair = PqKeyPair::generate();
    let mut pq_initiator =
        PqHandshake::new_initiator(&pq_initiator_keypair, &pq_responder_keypair.public, &[])
            .unwrap();
    let mut pq_responder = PqHandshake::new_responder(&pq_responder_keypair, &[]).unwrap();

    let hybrid_initiator_keypair = HybridKeyPair::generate();
    let hybrid_responder_keypair = HybridKeyPair::generate();
    let mut hybrid_initiator = HybridHandshake::new_initiator(
        &hybrid_initiator_keypair,
        &hybrid_responder_keypair.public,
        &[],
    )
    .unwrap();
    let mut hybrid_responder =
        HybridHandshake::new_responder(&hybrid_responder_keypair, &[]).unwrap();

    let mut message = vec![0u8; BUFFER_LEN];
    let mut payload_output = vec![0u8; BUFFER_LEN];
    let pq_message_1_len = pq_initiator.write_message(&[], &mut message).unwrap();
    let pq_message_1 = message[..pq_message_1_len].to_vec();
    let hybrid_message_1_len = hybrid_initiator.write_message(&[], &mut message).unwrap();
    let hybrid_message_1 = message[..hybrid_message_1_len].to_vec();

    assert_eq!(
        hybrid_responder.read_message(&pq_message_1, &mut payload_output),
        Err(Error::BadMessage),
    );
    assert_eq!(
        pq_responder.read_message(&hybrid_message_1, &mut payload_output),
        Err(Error::BadMessage),
    );
    assert!(!hybrid_responder.is_remote_authenticated());
    assert!(!pq_responder.is_remote_authenticated());
}

#[test]
fn pq_and_hybrid_reject_wrong_state_calls() {
    let pq_initiator = PqKeyPair::generate();
    let pq_responder = PqKeyPair::generate();
    let mut pq = PqHandshake::new_initiator(&pq_initiator, &pq_responder.public, &[]).unwrap();
    let mut output = [0u8; BUFFER_LEN];

    assert_eq!(
        pq.read_message(&[0u8; 3472], &mut output),
        Err(Error::WrongState),
    );

    let hybrid_initiator = HybridKeyPair::generate();
    let hybrid_responder = HybridKeyPair::generate();
    let mut hybrid = HybridHandshake::new_responder(&hybrid_responder, &[]).unwrap();

    assert_eq!(
        hybrid.write_message(&[], &mut output),
        Err(Error::WrongState),
    );
    assert!(
        HybridHandshake::new_initiator(&hybrid_initiator, &hybrid_responder.public, &[],).is_ok(),
    );
}
