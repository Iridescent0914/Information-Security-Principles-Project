import os
import socket
import select

from protocol import (
    TYPE_HANDSHAKE,
    TYPE_DATA,
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

from tun_utils import create_tun


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
    # Stage 5: TUN <-> encrypted UDP tunnel
    # ========================================================

    tun_fd, tun_name = create_tun("tjvpn0")

    print()
    print(f"[TUN] Created {tun_name}")
    print("[TUN] Configure in another terminal:")
    print("      sudo ip addr add 10.8.0.1/24 dev tjvpn0")
    print("      sudo ip link set tjvpn0 up")
    print("      sudo ip link set tjvpn0 mtu 1300")

    send_sequence = 0
    last_received_sequence = 0

    print()
    print("[TUNNEL] Server tunnel loop started")
    print("[TUNNEL] Waiting for IPv4 packets")

    try:
        while True:
            readable, _, _ = select.select(
                [tun_fd, sock],
                [],
                [],
            )

            # ------------------------------------------------
            # Kernel -> VMware tjvpn0 -> encrypted UDP -> Kali
            # ------------------------------------------------
            if tun_fd in readable:
                ip_packet = os.read(tun_fd, 65535)

                if not ip_packet:
                    continue

                ip_version = ip_packet[0] >> 4

                if ip_version != 4:
                    print(
                        f"[DROP] Non-IPv4 packet from TUN "
                        f"version={ip_version} len={len(ip_packet)}"
                    )
                    continue

                send_sequence += 1

                encrypted = encrypt_data(
                    session_key,
                    send_sequence,
                    ip_packet,
                )

                sock.sendto(
                    encrypted["packet"],
                    client_addr,
                )

                print(
                    f"[TUN->UDP] seq={send_sequence} "
                    f"ipv4_len={len(ip_packet)} "
                    f"udp_payload_len={len(encrypted['packet'])}"
                )

            # ------------------------------------------------
            # Kali encrypted UDP -> decrypt -> VMware tjvpn0
            # ------------------------------------------------
            if sock in readable:
                packet, addr = sock.recvfrom(65535)

                if addr != client_addr:
                    print(
                        "[DROP] UDP packet from unexpected address:",
                        addr,
                    )
                    continue

                try:
                    packet_type, sequence, payload = unpack_packet(
                        packet
                    )
                except ValueError as e:
                    print("[DROP] Invalid TJ packet:", e)
                    continue

                if packet_type == TYPE_CLOSE:
                    if sequence != 0 or payload != b"close":
                        print("[DROP] Invalid CLOSE packet")
                        continue

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
                    break

                if packet_type != TYPE_DATA:
                    print(
                        f"[DROP] Unexpected packet type "
                        f"{packet_type}"
                    )
                    continue

                try:
                    result = decrypt_data(
                        session_key,
                        packet,
                        last_received_sequence,
                    )

                except ReplayError as e:
                    print("[REPLAY] Packet rejected:", e)
                    continue

                except DataAuthenticationError as e:
                    print("[AES-GCM] Packet rejected:", e)
                    continue

                except ValueError as e:
                    print("[DROP] Invalid DATA packet:", e)
                    continue

                # 认证成功后才能推进序号
                last_received_sequence = result["sequence"]

                ip_packet = result["plaintext"]

                if not ip_packet:
                    print("[DROP] Empty decrypted packet")
                    continue

                ip_version = ip_packet[0] >> 4

                if ip_version != 4:
                    print(
                        f"[DROP] Decrypted non-IPv4 packet "
                        f"version={ip_version}"
                    )
                    continue

                os.write(
                    tun_fd,
                    ip_packet,
                )

                print(
                    f"[UDP->TUN] seq={result['sequence']} "
                    f"ipv4_len={len(ip_packet)}"
                )

    except KeyboardInterrupt:
        print()
        print("[INFO] Server interrupted")

    finally:
        os.close(tun_fd)
        sock.close()

        print("[TUN] tjvpn0 closed")
        print("[INFO] Secure tunnel server stopped")


if __name__ == "__main__":
    main()
