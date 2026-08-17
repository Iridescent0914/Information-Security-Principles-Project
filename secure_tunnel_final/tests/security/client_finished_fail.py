import os
import sys
import socket
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from protocol import (
    TYPE_HANDSHAKE,
    TYPE_CLOSE,
    HS_CLIENT_KEY_EXCHANGE,
    HS_SERVER_KEY_EXCHANGE,
    HS_CLIENT_FINISHED,
    HS_SERVER_FINISHED,
    HEADER_SIZE,
    pack_packet,
    unpack_packet,
)

from handshake import (
    PROTOCOL_VERSION,
    CIPHER_SUITE,
    pack_client_hello,
    unpack_server_hello,
    pack_key_exchange,
    unpack_key_exchange,
    pack_finished,
    unpack_finished,
)

from session import (
    encrypt_data,
    decrypt_data,
    IV_SIZE,
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


SERVER_PORT = 2026
CERT_PATH = "certs/server_cert.pem"


def certificate_to_der(pem_bytes):
    cert = x509.load_pem_x509_certificate(
        pem_bytes
    )

    return cert.public_bytes(
        serialization.Encoding.DER
    )


def send_handshake(sock, payload, server_addr):
    packet = pack_packet(
        TYPE_HANDSHAKE,
        0,
        payload,
    )

    sock.sendto(packet, server_addr)


def recv_handshake(sock):
    data, addr = sock.recvfrom(65535)

    packet_type, sequence, payload = unpack_packet(data)

    if packet_type != TYPE_HANDSHAKE:
        raise ValueError("expected HANDSHAKE packet")

    if sequence != 0:
        raise ValueError("handshake sequence must be 0")

    return payload, addr


def main():
    if len(sys.argv) != 2:
        print(
            f"Usage: python3 {sys.argv[0]} "
            "<SERVER_VPN_IP>"
        )
        sys.exit(1)

    server_ip = sys.argv[1]

    server_addr = (
        server_ip,
        SERVER_PORT,
    )

    with open(CERT_PATH, "rb") as f:
        trusted_certificate_pem = f.read()

    trusted_certificate_der = certificate_to_der(
        trusted_certificate_pem
    )

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
    )

    sock.settimeout(3)

    # ========================================================
    # 1. ClientHello
    # ========================================================

    client_random = os.urandom(16)

    client_hello_payload = pack_client_hello(
        client_random,
        (CIPHER_SUITE,),
    )

    send_handshake(
        sock,
        client_hello_payload,
        server_addr,
    )

    print("[HANDSHAKE] Sent ClientHello")
    print(
        "Server =",
        f"{server_ip}:{SERVER_PORT}",
    )
    print(
        "Protocol version =",
        hex(PROTOCOL_VERSION),
    )
    print(
        "Client Random =",
        client_random.hex(),
    )
    print(
        "Cipher Suites =",
        [hex(CIPHER_SUITE)],
    )

    # ========================================================
    # 2. ServerHello
    # ========================================================

    server_hello_payload, addr = recv_handshake(sock)

    if addr != server_addr:
        raise ValueError(
            "ServerHello from unexpected address"
        )

    (
        version,
        server_random,
        selected_suite,
        received_certificate_pem,
    ) = unpack_server_hello(
        server_hello_payload
    )

    print()
    print("[HANDSHAKE] Received ServerHello")
    print("Server address =", addr)
    print("Protocol version =", hex(version))
    print("Server Random =", server_random.hex())
    print("Selected Suite =", hex(selected_suite))
    print(
        "Certificate length =",
        len(received_certificate_pem),
    )

    if version != PROTOCOL_VERSION:
        raise ValueError(
            "unsupported protocol version"
        )

    if selected_suite != CIPHER_SUITE:
        raise ValueError(
            "unexpected cipher suite"
        )

    received_certificate_der = certificate_to_der(
        received_certificate_pem
    )

    if (
        received_certificate_der
        != trusted_certificate_der
    ):
        raise ValueError(
            "server certificate mismatch"
        )

    print("[CERT] Server certificate verified")

    # ========================================================
    # 3. ClientKeyExchange
    # ========================================================

    (
        client_private,
        client_public_bytes,
    ) = generate_ecdh_keypair()

    client_key_payload = pack_key_exchange(
        HS_CLIENT_KEY_EXCHANGE,
        client_public_bytes,
    )

    send_handshake(
        sock,
        client_key_payload,
        server_addr,
    )

    print()
    print("[HANDSHAKE] Sent ClientKeyExchange")
    print(
        "Client ECDH public key length =",
        len(client_public_bytes),
    )

    # ========================================================
    # 4. ServerKeyExchange
    # ========================================================

    server_key_payload, addr = recv_handshake(sock)

    if addr != server_addr:
        raise ValueError(
            "ServerKeyExchange from unexpected address"
        )

    server_public_bytes = unpack_key_exchange(
        server_key_payload,
        HS_SERVER_KEY_EXCHANGE,
    )

    print()
    print("[HANDSHAKE] Received ServerKeyExchange")
    print(
        "Server ECDH public key length =",
        len(server_public_bytes),
    )

    # ========================================================
    # 5. ECDH + Transcript + HKDF
    # ========================================================

    pre_master = compute_pre_master(
        client_private,
        server_public_bytes,
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
    # 6. Send ClientFinished
    # ========================================================

    client_verify_data = compute_finished(
        session_key,
        transcript_hash,
    )

    # Stage 7 negative test:
    # 故意翻转 ClientFinished VerifyData 的第一个 bit。
    bad_verify_data = bytearray(client_verify_data)
    bad_verify_data[0] ^= 0x01
    bad_verify_data = bytes(bad_verify_data)

    print()
    print("[TEST] Sending intentionally invalid ClientFinished")
    print("[TEST] Correct VerifyData =", client_verify_data.hex())
    print("[TEST] Tampered VerifyData =", bad_verify_data.hex())

    client_finished_payload = pack_finished(
        HS_CLIENT_FINISHED,
        bad_verify_data,
    )

    send_handshake(
        sock,
        client_finished_payload,
        server_addr,
    )

    print()
    print("[HANDSHAKE] Sent ClientFinished")

    # ========================================================
    # 7. Receive ServerFinished
    # ========================================================

    server_finished_payload, addr = recv_handshake(sock)

    if addr != server_addr:
        raise ValueError(
            "ServerFinished from unexpected address"
        )

    server_verify_data = unpack_finished(
        server_finished_payload,
        HS_SERVER_FINISHED,
    )

    print()
    print("[HANDSHAKE] Received ServerFinished")

    if not verify_finished(
        session_key,
        transcript_hash,
        server_verify_data,
    ):
        print(
            "[FINISHED] Server Finished verification FAILED"
        )
        raise ValueError(
            "Server Finished verification failed"
        )

    print("[FINISHED] Server Finished verified")

    # ========================================================
    # ESTABLISHED
    # ========================================================

    print()
    print("[STATE] ESTABLISHED")
    print("[INFO] Full handshake completed successfully")

        # ========================================================
    # Stage 4: Send encrypted DATA
    # ========================================================

    send_sequence = 0
    last_received_sequence = 0

    send_sequence += 1

    encrypted_message = encrypt_data(
        session_key,
        send_sequence,
        b"hello secure tunnel",
    )

    print()
    print("[DATA] Encrypt")
    print(
        "Sequence Number =",
        encrypted_message["sequence"],
    )
    print(
        "IV =",
        encrypted_message["iv"].hex(),
    )
    print(
        "Plaintext =",
        encrypted_message["plaintext"],
    )
    print(
        "Ciphertext =",
        encrypted_message["ciphertext"].hex(),
    )
    print(
        "Auth Tag =",
        encrypted_message["auth_tag"].hex(),
    )
    print(
        "Full Packet =",
        encrypted_message["packet"].hex(),
    )

    sock.sendto(
        encrypted_message["packet"],
        server_addr,
    )

    print("[DATA] Encrypted message sent")

    # ========================================================
    # Receive encrypted response
    # ========================================================

    response_packet, addr = sock.recvfrom(
        65535
    )

    if addr != server_addr:
        raise ValueError(
            "DATA response from unexpected address"
        )

    result = decrypt_data(
        session_key,
        response_packet,
        last_received_sequence,
    )

    last_received_sequence = result["sequence"]

    print()
    print("[DATA] Response decrypt success")
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

    print()
    print(
        "[INFO] Stage 4 basic DATA test complete"
    )


        # ========================================================
    # Stage 4B-1: Replay same DATA packet
    # ========================================================

    print()
    print("[TEST] Sending replayed DATA packet")

    # 原封不动再次发送 sequence = 1 的完整 DATA packet
    sock.sendto(
        encrypted_message["packet"],
        server_addr,
    )

    print(
        "[TEST] Replayed Sequence Number =",
        encrypted_message["sequence"],
    )

    time.sleep(0.3)


    # ========================================================
    # Stage 4B-2: Modify Ciphertext
    # ========================================================

    send_sequence += 1

    ciphertext_test = encrypt_data(
        session_key,
        send_sequence,
        b"tamper ciphertext",
    )

    tampered_packet = bytearray(
        ciphertext_test["packet"]
    )

    # 外层头 9B + IV 12B 后就是 Ciphertext
    ciphertext_offset = HEADER_SIZE + IV_SIZE

    tampered_packet[ciphertext_offset] ^= 0x01

    print()
    print("[TEST] Sending modified Ciphertext")
    print(
        "Sequence Number =",
        ciphertext_test["sequence"],
    )

    sock.sendto(
        bytes(tampered_packet),
        server_addr,
    )

    time.sleep(0.3)


    # ========================================================
    # Stage 4B-3: Modify Auth Tag
    # ========================================================

    send_sequence += 1

    tag_test = encrypt_data(
        session_key,
        send_sequence,
        b"tamper auth tag",
    )

    tampered_packet = bytearray(
        tag_test["packet"]
    )

    # DATA packet 最后 16B 是 Auth Tag。
    # 直接翻转最后一个字节。
    tampered_packet[-1] ^= 0x01

    print()
    print("[TEST] Sending modified Auth Tag")
    print(
        "Sequence Number =",
        tag_test["sequence"],
    )

    sock.sendto(
        bytes(tampered_packet),
        server_addr,
    )

    time.sleep(0.5)

    print()
    print("[INFO] Stage 4B attack packets sent")

        # ========================================================
    # Stage 4C: CLOSE
    # ========================================================

    close_packet = pack_packet(
        TYPE_CLOSE,
        0,
        b"close",
    )

    print()
    print("[CLOSE] Sending client CLOSE")

    sock.sendto(
        close_packet,
        server_addr,
    )

    close_response, addr = sock.recvfrom(
        65535
    )

    if addr != server_addr:
        raise ValueError(
            "CLOSE response from unexpected address"
        )

    packet_type, sequence, payload = unpack_packet(
        close_response
    )

    if packet_type != TYPE_CLOSE:
        raise ValueError(
            "expected CLOSE response"
        )

    if sequence != 0:
        raise ValueError(
            "CLOSE sequence must be 0"
        )

    if payload != b"close":
        raise ValueError(
            "invalid CLOSE response payload"
        )

    print("[CLOSE] Server CLOSE received")
    print("[STATE] CLOSED")

    sock.close()

    print()
    print("[INFO] Stage 4 complete")

if __name__ == "__main__":
    main()
