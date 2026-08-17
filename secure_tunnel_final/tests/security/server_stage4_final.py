import os
import socket

from protocol import (
    TYPE_HANDSHAKE,
    TYPE_CLOSE,
    HS_CLIENT_KEY_EXCHANGE,
    HS_SERVER_KEY_EXCHANGE,
    HS_CLIENT_FINISHED,
    HS_SERVER_FINISHED,
    pack_packet,
    unpack_packet,
)

from handshake import (
    PROTOCOL_VERSION,
    CIPHER_SUITE,
    pack_server_hello,
    unpack_client_hello,
    pack_key_exchange,
    unpack_key_exchange,
    pack_finished,
    unpack_finished,
)

from session import (
    encrypt_data,
    decrypt_data,
    ReplayError,
    DataAuthenticationError,
)

from crypto_utils import (
    generate_ecdh_keypair,
    compute_pre_master,
    compute_transcript_hash,
    derive_session_key,
    sha256_hex,
    compute_finished,
    verify_finished,
)


HOST = "0.0.0.0"
PORT = 2026
CERT_PATH = "certs/server_cert.pem"


def recv_handshake(sock):
    data, addr = sock.recvfrom(65535)

    packet_type, sequence, payload = unpack_packet(data)

    if packet_type != TYPE_HANDSHAKE:
        raise ValueError("expected HANDSHAKE packet")

    if sequence != 0:
        raise ValueError("handshake sequence must be 0")

    return payload, addr


def send_handshake(sock, payload, addr):
    packet = pack_packet(
        TYPE_HANDSHAKE,
        0,
        payload,
    )

    sock.sendto(packet, addr)


def main():
    with open(CERT_PATH, "rb") as f:
        certificate_pem = f.read()

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
    )

    sock.bind((HOST, PORT))

    print(f"[INFO] Server listening on UDP {PORT}")

    # ========================================================
    # 1. ClientHello
    # ========================================================

    client_hello_payload, client_addr = recv_handshake(sock)

    (
        version,
        client_random,
        suites,
    ) = unpack_client_hello(
        client_hello_payload
    )

    print()
    print("[HANDSHAKE] Received ClientHello")
    print("Client address =", client_addr)
    print("Protocol version =", hex(version))
    print("Client Random =", client_random.hex())
    print("Cipher Suites =", [hex(x) for x in suites])

    if version != PROTOCOL_VERSION:
        raise ValueError("unsupported protocol version")

    if CIPHER_SUITE not in suites:
        raise ValueError("no supported cipher suite")

    # ========================================================
    # 2. ServerHello
    # ========================================================

    server_random = os.urandom(16)

    server_hello_payload = pack_server_hello(
        server_random,
        CIPHER_SUITE,
        certificate_pem,
    )

    send_handshake(
        sock,
        server_hello_payload,
        client_addr,
    )

    print()
    print("[HANDSHAKE] Sent ServerHello")
    print("Server Random =", server_random.hex())
    print("Selected Suite =", hex(CIPHER_SUITE))
    print(
        "Certificate length =",
        len(certificate_pem),
    )

    # ========================================================
    # 3. ClientKeyExchange
    # ========================================================

    client_key_payload, addr = recv_handshake(sock)

    if addr != client_addr:
        raise ValueError(
            "ClientKeyExchange from unexpected address"
        )

    client_public_bytes = unpack_key_exchange(
        client_key_payload,
        HS_CLIENT_KEY_EXCHANGE,
    )

    print()
    print("[HANDSHAKE] Received ClientKeyExchange")
    print(
        "Client ECDH public key length =",
        len(client_public_bytes),
    )

    # ========================================================
    # 4. ServerKeyExchange
    # ========================================================

    (
        server_private,
        server_public_bytes,
    ) = generate_ecdh_keypair()

    server_key_payload = pack_key_exchange(
        HS_SERVER_KEY_EXCHANGE,
        server_public_bytes,
    )

    send_handshake(
        sock,
        server_key_payload,
        client_addr,
    )

    print()
    print("[HANDSHAKE] Sent ServerKeyExchange")
    print(
        "Server ECDH public key length =",
        len(server_public_bytes),
    )

    # ========================================================
    # 5. ECDH + Transcript + HKDF
    # ========================================================

    pre_master = compute_pre_master(
        server_private,
        client_public_bytes,
    )

    transcript_hash = compute_transcript_hash(
        client_hello_payload,
        server_hello_payload,
        client_key_payload,
        server_key_payload,
    )

    session_key = derive_session_key(
        pre_master,
        client_random,
        server_random,
        transcript_hash,
    )

    print()
    print("[CRYPTO] ECDH complete")
    print("Pre-Master length =", len(pre_master))
    print(
        "Pre-Master SHA256 =",
        sha256_hex(pre_master),
    )

    print()
    print(
        "[TRANSCRIPT] SHA256 =",
        transcript_hash.hex(),
    )

    print()
    print("[CRYPTO] HKDF complete")
    print("Session Key length =", len(session_key))
    print(
        "Session Key SHA256 =",
        sha256_hex(session_key),
    )

    # ========================================================
    # 6. Receive ClientFinished
    # ========================================================

    client_finished_payload, addr = recv_handshake(sock)

    if addr != client_addr:
        raise ValueError(
            "ClientFinished from unexpected address"
        )

    client_verify_data = unpack_finished(
        client_finished_payload,
        HS_CLIENT_FINISHED,
    )

    print()
    print("[HANDSHAKE] Received ClientFinished")

    if not verify_finished(
        session_key,
        transcript_hash,
        client_verify_data,
    ):
        print("[FINISHED] Client Finished verification FAILED")
        raise ValueError(
            "Client Finished verification failed"
        )

    print("[FINISHED] Client Finished verified")

    # ========================================================
    # 7. Send ServerFinished
    # ========================================================

    server_verify_data = compute_finished(
        session_key,
        transcript_hash,
    )

    server_finished_payload = pack_finished(
        HS_SERVER_FINISHED,
        server_verify_data,
    )

    send_handshake(
        sock,
        server_finished_payload,
        client_addr,
    )

    print()
    print("[HANDSHAKE] Sent ServerFinished")
    print("[FINISHED] Server Finished generated")

    # ========================================================
    # ESTABLISHED
    # ========================================================

    print()
    print("[STATE] ESTABLISHED")
    print("[INFO] Full handshake completed successfully")

        # ========================================================
    # Stage 4: Receive encrypted DATA
    # ========================================================

    last_received_sequence = 0
    send_sequence = 0

    print()
    print("[DATA] Waiting for encrypted DATA packet")

    data_packet, addr = sock.recvfrom(65535)

    if addr != client_addr:
        raise ValueError(
            "DATA packet from unexpected address"
        )

    result = decrypt_data(
        session_key,
        data_packet,
        last_received_sequence,
    )

    # 认证成功后才推进接收序号
    last_received_sequence = result["sequence"]

    print()
    print("[DATA] Decrypt success")
    print(
        "Sequence Number =",
        result["sequence"],
    )
    print(
        "IV =",
        result["iv"].hex(),
    )
    print(
        "Ciphertext =",
        result["ciphertext"].hex(),
    )
    print(
        "Auth Tag =",
        result["auth_tag"].hex(),
    )
    print(
        "Plaintext =",
        result["plaintext"],
    )

    # ========================================================
    # Send encrypted response
    # ========================================================

    send_sequence += 1

    response = encrypt_data(
        session_key,
        send_sequence,
        b"secure tunnel response",
    )

    sock.sendto(
        response["packet"],
        client_addr,
    )

    print()
    print("[DATA] Encrypted response sent")
    print(
        "Sequence Number =",
        response["sequence"],
    )
    print(
        "IV =",
        response["iv"].hex(),
    )
    print(
        "Plaintext =",
        response["plaintext"],
    )
    print(
        "Ciphertext =",
        response["ciphertext"].hex(),
    )
    print(
        "Auth Tag =",
        response["auth_tag"].hex(),
    )
    print(
        "Full Packet =",
        response["packet"].hex(),
    )

    print()
    print(
        "[INFO] Stage 4 basic DATA test complete"
    )

        # ========================================================
    # Stage 4B-1: Replay test
    # ========================================================

    print()
    print("[TEST] Waiting for replayed DATA packet")

    replay_packet, addr = sock.recvfrom(65535)

    if addr != client_addr:
        raise ValueError(
            "replay packet from unexpected address"
        )

    try:
        replay_result = decrypt_data(
            session_key,
            replay_packet,
            last_received_sequence,
        )

    except ReplayError as e:
        print("[PASS] Replay packet rejected")
        print("[REPLAY]", e)

    else:
        raise AssertionError(
            "replayed packet should have been rejected"
        )


    # ========================================================
    # Stage 4B-2: Modified Ciphertext
    # ========================================================

    print()
    print("[TEST] Waiting for modified Ciphertext packet")

    tampered_ciphertext_packet, addr = sock.recvfrom(
        65535
    )

    if addr != client_addr:
        raise ValueError(
            "tampered packet from unexpected address"
        )

    try:
        result = decrypt_data(
            session_key,
            tampered_ciphertext_packet,
            last_received_sequence,
        )

    except DataAuthenticationError as e:
        print("[PASS] Modified Ciphertext rejected")
        print("[AES-GCM]", e)

    else:
        raise AssertionError(
            "modified Ciphertext should have been rejected"
        )


    # ========================================================
    # Stage 4B-3: Modified Auth Tag
    # ========================================================

    print()
    print("[TEST] Waiting for modified Auth Tag packet")

    tampered_tag_packet, addr = sock.recvfrom(
        65535
    )

    if addr != client_addr:
        raise ValueError(
            "tampered tag packet from unexpected address"
        )

    try:
        result = decrypt_data(
            session_key,
            tampered_tag_packet,
            last_received_sequence,
        )

    except DataAuthenticationError as e:
        print("[PASS] Modified Auth Tag rejected")
        print("[AES-GCM]", e)

    else:
        raise AssertionError(
            "modified Auth Tag should have been rejected"
        )


    print()
    print("[INFO] Stage 4B security tests complete")

        # ========================================================
    # Stage 4C: CLOSE
    # ========================================================

    print()
    print("[CLOSE] Waiting for client CLOSE")

    close_packet, addr = sock.recvfrom(65535)

    if addr != client_addr:
        raise ValueError(
            "CLOSE packet from unexpected address"
        )

    packet_type, sequence, payload = unpack_packet(
        close_packet
    )

    if packet_type != TYPE_CLOSE:
        raise ValueError(
            "expected CLOSE packet"
        )

    if sequence != 0:
        raise ValueError(
            "CLOSE sequence must be 0"
        )

    if payload != b"close":
        raise ValueError(
            "invalid CLOSE payload"
        )

    print("[CLOSE] Client CLOSE received")

    close_response = pack_packet(
        TYPE_CLOSE,
        0,
        b"close",
    )

    sock.sendto(
        close_response,
        client_addr,
    )

    print("[CLOSE] Server CLOSE sent")
    print("[STATE] CLOSED")

    sock.close()

    print()
    print("[INFO] Stage 4 complete")

if __name__ == "__main__":
    main()
