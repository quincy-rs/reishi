//! Integration tests using the full quinn QUIC stack.
//!
//! These tests verify that reishi-quinn works correctly as a drop-in
//! crypto provider for quinn, exercising the complete connection lifecycle:
//! handshake, data transfer, peer identity, and error cases.

use std::net::UdpSocket;
use std::sync::Arc;

use quinn::{ClientConfig, Endpoint, EndpointConfig, ServerConfig};
use rand_core::OsRng;
use reishi_quinn::{
    KeyPair, NoiseConfigBuilder, PeerIdentity, REISHI_V1_QUIC_V1, noise_handshake_token_key,
    noise_hmac_key,
};

/// Build an EndpointConfig that supports our custom QUIC version.
fn endpoint_config() -> EndpointConfig {
    let mut config = EndpointConfig::new(noise_hmac_key());
    config.supported_versions(vec![REISHI_V1_QUIC_V1]);
    config
}

/// Create a server endpoint on a random loopback port.
fn server_endpoint(server_config: ServerConfig) -> Endpoint {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let runtime = quinn::default_runtime().unwrap();
    Endpoint::new(endpoint_config(), Some(server_config), socket, runtime).unwrap()
}

/// Create a client-only endpoint on a random loopback port.
fn client_endpoint() -> Endpoint {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let runtime = quinn::default_runtime().unwrap();
    Endpoint::new(endpoint_config(), None, socket, runtime).unwrap()
}

/// Generate a server config from a keypair.
fn make_server_config(kp: KeyPair) -> ServerConfig {
    let noise = NoiseConfigBuilder::new(kp).build_server_config().unwrap();
    ServerConfig::new(Arc::new(noise), noise_handshake_token_key())
}

/// Generate a client config from a keypair and the server's public key.
fn make_client_config(kp: KeyPair, server_public: reishi_quinn::PublicKey) -> ClientConfig {
    let noise = NoiseConfigBuilder::new(kp)
        .with_remote_public(server_public)
        .build_client_config()
        .unwrap();
    let mut config = ClientConfig::new(Arc::new(noise));
    config.version(REISHI_V1_QUIC_V1);
    config
}

// =========================================================================
// Handshake + bidirectional data transfer
// =========================================================================

#[tokio::test]
async fn handshake_and_bidirectional_data() {
    let server_kp = KeyPair::generate(&mut OsRng);
    let server_public = server_kp.public;
    let client_kp = KeyPair::generate(&mut OsRng);

    let server = server_endpoint(make_server_config(server_kp));
    let server_addr = server.local_addr().unwrap();
    let client = client_endpoint();

    let client_config = make_client_config(client_kp, server_public);
    let connecting = client
        .connect_with(client_config, server_addr, "server")
        .unwrap();

    let (client_conn, server_conn) = tokio::join!(async { connecting.await.unwrap() }, async {
        server.accept().await.unwrap().await.unwrap()
    },);

    // Client → Server
    let (mut c_send, mut c_recv) = client_conn.open_bi().await.unwrap();
    c_send.write_all(b"hello from client").await.unwrap();
    c_send.finish().unwrap();

    let (mut s_send, mut s_recv) = server_conn.accept_bi().await.unwrap();
    let data = s_recv.read_to_end(4096).await.unwrap();
    assert_eq!(data, b"hello from client");

    // Server → Client
    s_send.write_all(b"hello from server").await.unwrap();
    s_send.finish().unwrap();

    let data = c_recv.read_to_end(4096).await.unwrap();
    assert_eq!(data, b"hello from server");

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

// =========================================================================
// Peer identity verification
// =========================================================================

#[tokio::test]
async fn peer_identity_available() {
    let server_kp = KeyPair::generate(&mut OsRng);
    let server_public = server_kp.public;
    let client_kp = KeyPair::generate(&mut OsRng);
    let client_public = client_kp.public;

    let server = server_endpoint(make_server_config(server_kp));
    let server_addr = server.local_addr().unwrap();
    let client = client_endpoint();

    let client_config = make_client_config(client_kp, server_public);
    let connecting = client
        .connect_with(client_config, server_addr, "server")
        .unwrap();

    let (client_conn, server_conn) = tokio::join!(async { connecting.await.unwrap() }, async {
        server.accept().await.unwrap().await.unwrap()
    },);

    // Client sees server's public key
    let client_peer = client_conn
        .peer_identity()
        .expect("client should have peer identity")
        .downcast::<PeerIdentity>()
        .expect("should downcast to PeerIdentity");
    assert_eq!(client_peer.public_key, *server_public.as_bytes());

    // Server sees client's public key
    let server_peer = server_conn
        .peer_identity()
        .expect("server should have peer identity")
        .downcast::<PeerIdentity>()
        .expect("should downcast to PeerIdentity");
    assert_eq!(server_peer.public_key, *client_public.as_bytes());

    // Handshake hashes match
    assert_eq!(client_peer.handshake_hash, server_peer.handshake_hash);

    client_conn.close(0u32.into(), b"done");
    server_conn.close(0u32.into(), b"done");
}

// =========================================================================
// Multiple sequential connections to the same server
// =========================================================================

#[tokio::test]
async fn multiple_connections() {
    let server_kp = KeyPair::generate(&mut OsRng);
    let server_public = server_kp.public;

    let server = server_endpoint(make_server_config(server_kp));
    let server_addr = server.local_addr().unwrap();
    let client = client_endpoint();

    for i in 0u8..3 {
        let client_kp = KeyPair::generate(&mut OsRng);
        let client_config = make_client_config(client_kp, server_public);
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
// Unidirectional streams
// =========================================================================

#[tokio::test]
async fn unidirectional_streams() {
    let server_kp = KeyPair::generate(&mut OsRng);
    let server_public = server_kp.public;
    let client_kp = KeyPair::generate(&mut OsRng);

    let server = server_endpoint(make_server_config(server_kp));
    let server_addr = server.local_addr().unwrap();
    let client = client_endpoint();

    let client_config = make_client_config(client_kp, server_public);
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
// Wrong server key → handshake failure
// =========================================================================

#[tokio::test]
async fn wrong_server_key_rejected() {
    let server_kp = KeyPair::generate(&mut OsRng);
    let wrong_kp = KeyPair::generate(&mut OsRng);
    let client_kp = KeyPair::generate(&mut OsRng);

    let server = server_endpoint(make_server_config(server_kp));
    let server_addr = server.local_addr().unwrap();
    let client = client_endpoint();

    // Client expects the wrong server public key
    let client_config = make_client_config(client_kp, wrong_kp.public);
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
        Ok(Ok(_)) => panic!("connection should have failed with wrong server key"),
        Ok(Err(_)) => {} // expected: connection error
        Err(_) => panic!("timed out waiting for handshake failure"),
    }

    server_task.abort();
}

// =========================================================================
// Export keying material
// =========================================================================

#[tokio::test]
async fn export_keying_material() {
    let server_kp = KeyPair::generate(&mut OsRng);
    let server_public = server_kp.public;
    let client_kp = KeyPair::generate(&mut OsRng);

    let server = server_endpoint(make_server_config(server_kp));
    let server_addr = server.local_addr().unwrap();
    let client = client_endpoint();

    let client_config = make_client_config(client_kp, server_public);
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
