//! PQ integration tests using the full quinn QUIC stack.
//!
//! These tests verify that the hybrid PQ Noise IK handshake works correctly
//! as a drop-in crypto provider for quinn, exercising the complete connection
//! lifecycle: handshake, data transfer, peer identity, EKM, and error cases.

#![cfg(feature = "pq")]

use std::net::UdpSocket;
use std::sync::Arc;

use quinn::{ClientConfig, Endpoint, EndpointConfig, ServerConfig};
use rand_core::OsRng;
use reishi_quinn::{
    PeerIdentity, PqKeyPair, PqNoiseConfigBuilder, REISHI_PQ_V1_QUIC_V1, noise_handshake_token_key,
    noise_hmac_key,
};

/// Build an EndpointConfig that supports the PQ QUIC version.
fn pq_endpoint_config() -> EndpointConfig {
    let mut config = EndpointConfig::new(noise_hmac_key());
    config.supported_versions(vec![REISHI_PQ_V1_QUIC_V1]);
    config
}

/// Create a PQ server endpoint on a random loopback port.
fn pq_server_endpoint(server_config: ServerConfig) -> Endpoint {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let runtime = quinn::default_runtime().unwrap();
    Endpoint::new(pq_endpoint_config(), Some(server_config), socket, runtime).unwrap()
}

/// Create a PQ client-only endpoint on a random loopback port.
fn pq_client_endpoint() -> Endpoint {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let runtime = quinn::default_runtime().unwrap();
    Endpoint::new(pq_endpoint_config(), None, socket, runtime).unwrap()
}

/// Generate a PQ server config from a keypair.
fn make_pq_server_config(kp: PqKeyPair) -> ServerConfig {
    let noise = PqNoiseConfigBuilder::new(kp).build_server_config().unwrap();
    ServerConfig::new(Arc::new(noise), noise_handshake_token_key())
}

/// Generate a PQ client config from a keypair and the server's PQ public key.
fn make_pq_client_config(kp: PqKeyPair, server_public: reishi_quinn::PqPublicKey) -> ClientConfig {
    let noise = PqNoiseConfigBuilder::new(kp)
        .with_remote_public(server_public)
        .build_client_config()
        .unwrap();
    let mut config = ClientConfig::new(Arc::new(noise));
    config.version(REISHI_PQ_V1_QUIC_V1);
    config
}

// =========================================================================
// PQ handshake + bidirectional data transfer
// =========================================================================

#[tokio::test]
async fn pq_handshake_and_bidirectional_data() {
    let server_kp = PqKeyPair::generate(&mut OsRng);
    let server_public = server_kp.public.clone();
    let client_kp = PqKeyPair::generate(&mut OsRng);

    let server = pq_server_endpoint(make_pq_server_config(server_kp));
    let server_addr = server.local_addr().unwrap();
    let client = pq_client_endpoint();

    let client_config = make_pq_client_config(client_kp, server_public);
    let connecting = client
        .connect_with(client_config, server_addr, "server")
        .unwrap();

    let (client_conn, server_conn) = tokio::join!(async { connecting.await.unwrap() }, async {
        server.accept().await.unwrap().await.unwrap()
    },);

    // Client → Server
    let (mut c_send, mut c_recv) = client_conn.open_bi().await.unwrap();
    c_send.write_all(b"hello from PQ client").await.unwrap();
    c_send.finish().unwrap();

    let (mut s_send, mut s_recv) = server_conn.accept_bi().await.unwrap();
    let data = s_recv.read_to_end(4096).await.unwrap();
    assert_eq!(data, b"hello from PQ client");

    // Server → Client
    s_send.write_all(b"hello from PQ server").await.unwrap();
    s_send.finish().unwrap();

    let data = c_recv.read_to_end(4096).await.unwrap();
    assert_eq!(data, b"hello from PQ server");

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

// =========================================================================
// PQ peer identity verification
// =========================================================================

#[tokio::test]
async fn pq_peer_identity_available() {
    let server_kp = PqKeyPair::generate(&mut OsRng);
    let server_public = server_kp.public.clone();
    let client_kp = PqKeyPair::generate(&mut OsRng);
    let client_public = client_kp.public.clone();

    let server = pq_server_endpoint(make_pq_server_config(server_kp));
    let server_addr = server.local_addr().unwrap();
    let client = pq_client_endpoint();

    let client_config = make_pq_client_config(client_kp, server_public.clone());
    let connecting = client
        .connect_with(client_config, server_addr, "server")
        .unwrap();

    let (client_conn, server_conn) = tokio::join!(async { connecting.await.unwrap() }, async {
        server.accept().await.unwrap().await.unwrap()
    },);

    // Client sees server's DH public key
    let client_peer = client_conn
        .peer_identity()
        .expect("client should have peer identity")
        .downcast::<PeerIdentity>()
        .expect("should downcast to PeerIdentity");
    assert_eq!(
        client_peer.public_key,
        *server_public.dh_public().as_bytes()
    );

    // Client sees server's full PQ public key
    let client_pq = client_peer
        .pq_public_key
        .as_ref()
        .expect("PQ public key should be present");
    assert_eq!(
        client_pq.dh_public().as_bytes(),
        server_public.dh_public().as_bytes()
    );
    assert_eq!(client_pq.kem_ek(), server_public.kem_ek());

    // Server sees client's DH public key
    let server_peer = server_conn
        .peer_identity()
        .expect("server should have peer identity")
        .downcast::<PeerIdentity>()
        .expect("should downcast to PeerIdentity");
    assert_eq!(
        server_peer.public_key,
        *client_public.dh_public().as_bytes()
    );

    // Server sees client's full PQ public key
    let server_pq = server_peer
        .pq_public_key
        .as_ref()
        .expect("PQ public key should be present");
    assert_eq!(
        server_pq.dh_public().as_bytes(),
        client_public.dh_public().as_bytes()
    );
    assert_eq!(server_pq.kem_ek(), client_public.kem_ek());

    // Handshake hashes match
    assert_eq!(client_peer.handshake_hash, server_peer.handshake_hash);

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

// =========================================================================
// PQ multiple sequential connections
// =========================================================================

#[tokio::test]
async fn pq_multiple_connections() {
    let server_kp = PqKeyPair::generate(&mut OsRng);
    let server_public = server_kp.public.clone();

    let server = pq_server_endpoint(make_pq_server_config(server_kp));
    let server_addr = server.local_addr().unwrap();
    let client = pq_client_endpoint();

    for i in 0u8..3 {
        let client_kp = PqKeyPair::generate(&mut OsRng);
        let client_config = make_pq_client_config(client_kp, server_public.clone());
        let connecting = client
            .connect_with(client_config, server_addr, "server")
            .unwrap();

        let (client_conn, server_conn) = tokio::join!(async { connecting.await.unwrap() }, async {
            server.accept().await.unwrap().await.unwrap()
        },);

        let mut send = client_conn.open_uni().await.unwrap();
        send.write_all(&[i; 8]).await.unwrap();
        send.finish().unwrap();

        let mut recv = server_conn.accept_uni().await.unwrap();
        let data = recv.read_to_end(4096).await.unwrap();
        assert_eq!(data, vec![i; 8]);

        client_conn.close(0u32.into(), b"done");
        server_conn.close(0u32.into(), b"done");
    }
}

// =========================================================================
// PQ unidirectional streams with large payload
// =========================================================================

#[tokio::test]
async fn pq_unidirectional_streams() {
    let server_kp = PqKeyPair::generate(&mut OsRng);
    let server_public = server_kp.public.clone();
    let client_kp = PqKeyPair::generate(&mut OsRng);

    let server = pq_server_endpoint(make_pq_server_config(server_kp));
    let server_addr = server.local_addr().unwrap();
    let client = pq_client_endpoint();

    let client_config = make_pq_client_config(client_kp, server_public);
    let connecting = client
        .connect_with(client_config, server_addr, "server")
        .unwrap();

    let (client_conn, server_conn) = tokio::join!(async { connecting.await.unwrap() }, async {
        server.accept().await.unwrap().await.unwrap()
    },);

    // Send a larger payload over a unidirectional stream
    let payload = vec![0xABu8; 16384];
    let mut send = client_conn.open_uni().await.unwrap();
    send.write_all(&payload).await.unwrap();
    send.finish().unwrap();

    let mut recv = server_conn.accept_uni().await.unwrap();
    let data = recv.read_to_end(32768).await.unwrap();
    assert_eq!(data, payload);

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

// =========================================================================
// PQ wrong server key → handshake failure
// =========================================================================

#[tokio::test]
async fn pq_wrong_server_key_rejected() {
    let server_kp = PqKeyPair::generate(&mut OsRng);
    let wrong_kp = PqKeyPair::generate(&mut OsRng);
    let client_kp = PqKeyPair::generate(&mut OsRng);

    let server = pq_server_endpoint(make_pq_server_config(server_kp));
    let server_addr = server.local_addr().unwrap();
    let client = pq_client_endpoint();

    // Client expects the wrong server PQ public key
    let client_config = make_pq_client_config(client_kp, wrong_kp.public);
    let connecting = client
        .connect_with(client_config, server_addr, "server")
        .unwrap();

    // Accept on the server so the handshake actually proceeds and fails.
    let server_task = tokio::spawn(async move {
        if let Some(incoming) = server.accept().await {
            let _ = incoming.await;
        }
    });

    // The handshake should fail on the client side.
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), connecting).await;

    match result {
        Ok(Ok(_)) => panic!("connection should have failed with wrong PQ server key"),
        Ok(Err(_)) => {} // expected: connection error
        Err(_) => panic!("timed out waiting for PQ handshake failure"),
    }

    server_task.abort();
}

// =========================================================================
// PQ export keying material
// =========================================================================

#[tokio::test]
async fn pq_export_keying_material() {
    let server_kp = PqKeyPair::generate(&mut OsRng);
    let server_public = server_kp.public.clone();
    let client_kp = PqKeyPair::generate(&mut OsRng);

    let server = pq_server_endpoint(make_pq_server_config(server_kp));
    let server_addr = server.local_addr().unwrap();
    let client = pq_client_endpoint();

    let client_config = make_pq_client_config(client_kp, server_public);
    let connecting = client
        .connect_with(client_config, server_addr, "server")
        .unwrap();

    let (client_conn, server_conn) = tokio::join!(async { connecting.await.unwrap() }, async {
        server.accept().await.unwrap().await.unwrap()
    },);

    // Both sides derive the same EKM for the same label/context.
    let mut client_ekm = [0u8; 64];
    let mut server_ekm = [0u8; 64];
    client_conn
        .export_keying_material(&mut client_ekm, b"test label", b"test context")
        .unwrap();
    server_conn
        .export_keying_material(&mut server_ekm, b"test label", b"test context")
        .unwrap();
    assert_eq!(client_ekm, server_ekm);

    // Different labels produce different output.
    let mut other_ekm = [0u8; 64];
    client_conn
        .export_keying_material(&mut other_ekm, b"other label", b"test context")
        .unwrap();
    assert_ne!(client_ekm, other_ekm);

    // Different contexts produce different output.
    client_conn
        .export_keying_material(&mut other_ekm, b"test label", b"other context")
        .unwrap();
    assert_ne!(client_ekm, other_ekm);

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

// =========================================================================
// PQ prologue mismatch → handshake failure
// =========================================================================

#[tokio::test]
async fn pq_prologue_mismatch_rejected() {
    let server_kp = PqKeyPair::generate(&mut OsRng);
    let server_public = server_kp.public.clone();
    let client_kp = PqKeyPair::generate(&mut OsRng);

    let server_noise = PqNoiseConfigBuilder::new(server_kp)
        .with_prologue(b"server-prologue".to_vec())
        .build_server_config()
        .unwrap();
    let server_config = ServerConfig::new(Arc::new(server_noise), noise_handshake_token_key());

    let server = pq_server_endpoint(server_config);
    let server_addr = server.local_addr().unwrap();
    let client = pq_client_endpoint();

    let client_noise = PqNoiseConfigBuilder::new(client_kp)
        .with_remote_public(server_public)
        .with_prologue(b"client-prologue".to_vec()) // mismatched!
        .build_client_config()
        .unwrap();
    let mut client_config = ClientConfig::new(Arc::new(client_noise));
    client_config.version(REISHI_PQ_V1_QUIC_V1);

    let connecting = client
        .connect_with(client_config, server_addr, "server")
        .unwrap();

    let server_task = tokio::spawn(async move {
        if let Some(incoming) = server.accept().await {
            let _ = incoming.await;
        }
    });

    let result = tokio::time::timeout(std::time::Duration::from_secs(5), connecting).await;

    match result {
        Ok(Ok(_)) => panic!("connection should have failed with mismatched prologue"),
        Ok(Err(_)) => {} // expected
        Err(_) => panic!("timed out waiting for handshake failure"),
    }

    server_task.abort();
}
