//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use attest::client_connection;
use attest::hsm_enclave::*;

#[test]
fn test_hsm_enclave_happy_path() -> Result<()> {
    // Spin up a handshake for the server-side.
    let keypair =
        snow::Builder::new(client_connection::NOISE_PATTERN.parse()?).generate_keypair()?;
    let mut server_hs = snow::Builder::new(client_connection::NOISE_PATTERN.parse()?)
        .local_private_key(&keypair.private)
        .build_responder()?;

    // Spin up the client connection establishment.
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&keypair.public);
    let establishment = ClientConnectionEstablishment::new(public_key, vec![[1u8; 32]])?;

    // Give the establishment message to the server.
    let mut payload = vec![0u8; 32];
    let read_size = server_hs.read_message(establishment.initial_request(), &mut payload)?;
    assert_eq!(read_size, 32);
    assert_eq!(payload, [1u8; 32]);

    // Send message back to client, finish handshake.
    let mut message = vec![0u8; 80];
    let write_size = server_hs.write_message(&payload, &mut message)?;
    assert_eq!(write_size, 80);
    assert!(server_hs.is_handshake_finished());
    let mut server_transport = server_hs.into_transport_mode()?;

    // This should complete our connection establishment, now.
    let mut conn = establishment.complete(&message)?;

    // Send message server to client.
    let mut svr_cli_message = vec![0u8; 19]; // size=3 + overhead=16
    let svr_cli_write_size = server_transport.write_message(&[7, 8, 9], &mut svr_cli_message)?;
    assert_eq!(svr_cli_write_size, 19);
    assert_eq!([7, 8, 9], conn.recv(&svr_cli_message)?.as_slice());

    // Send message client to server.
    let cli_svr_message = conn.send(&[0xa, 0xb, 0xc])?;
    let mut cli_svr_payload = vec![0u8; 3];
    let cli_svr_read_size =
        server_transport.read_message(&cli_svr_message, &mut cli_svr_payload)?;
    assert_eq!(cli_svr_read_size, 3);
    assert_eq!([0xAu8, 0xBu8, 0xCu8], cli_svr_payload.as_slice());

    Ok(())
}

#[test]
fn test_hsm_enclave_codehash_mismatch() -> Result<()> {
    // Spin up a handshake for the server-side.
    let keypair =
        snow::Builder::new(client_connection::NOISE_PATTERN.parse()?).generate_keypair()?;
    let mut server_hs = snow::Builder::new(client_connection::NOISE_PATTERN.parse()?)
        .local_private_key(&keypair.private)
        .build_responder()?;

    // Spin up the client connection establishment.
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&keypair.public);
    let establishment = ClientConnectionEstablishment::new(public_key, vec![[1u8; 32]])?;

    // Give the establishment message to the server.
    let mut payload = vec![0u8; 32];
    let read_size = server_hs.read_message(establishment.initial_request(), &mut payload)?;
    assert_eq!(read_size, 32);
    assert_eq!(payload, [1u8; 32]);

    // Send message back to client, finish handshake.
    let mismatched_payload = vec![2u8; 32];
    let mut message = vec![0u8; 80];
    let write_size = server_hs.write_message(&mismatched_payload, &mut message)?;
    assert_eq!(write_size, 80);

    // This should complete our connection establishment, now.
    let out = establishment.complete(message.as_slice());
    assert!(out.is_err());

    Ok(())
}
