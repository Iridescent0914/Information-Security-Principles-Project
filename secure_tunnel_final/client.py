import os
import sys
import socket
import select
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from protocol import (
    TYPE_HANDSHAKE,
    TYPE_DATA,
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

    client_finished_payload = pack_finished(
        HS_CLIENT_FINISHED,
        client_verify_data,
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
    # Stage 5: TUN <-> encrypted UDP tunnel
    # ========================================================

    # 握手阶段使用了 3 秒 timeout。
    # 进入长期隧道循环后恢复为 blocking socket，
    # select() 负责等待事件。
    sock.settimeout(None)

    tun_fd, tun_name = create_tun("tjvpn0")

    print()
    print(f"[TUN] Created {tun_name}")
    print("[TUN] Configure in another terminal:")
    print("      sudo ip addr add 10.8.0.2/24 dev tjvpn0")
    print("      sudo ip link set tjvpn0 up")
    print("      sudo ip link set tjvpn0 mtu 1300")

    send_sequence = 0
    last_received_sequence = 0

    print()
    print("[TUNNEL] Client tunnel loop started")
    print("[TUNNEL] Waiting for IPv4 packets")

    try:
        while True:
            readable, _, _ = select.select(
                [tun_fd, sock],
                [],
                [],
            )

            # ------------------------------------------------
            # Kali kernel -> tjvpn0 -> encrypt -> UDP
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
                    server_addr,
                )

                print(
                    f"[TUN->UDP] seq={send_sequence} "
                    f"ipv4_len={len(ip_packet)} "
                    f"udp_payload_len={len(encrypted['packet'])}"
                )

            # ------------------------------------------------
            # VMware UDP -> decrypt -> Kali tjvpn0
            # ------------------------------------------------
            if sock in readable:
                packet, addr = sock.recvfrom(65535)

                if addr != server_addr:
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

                    print("[CLOSE] Server CLOSE received")
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
        print("[CLOSE] Sending client CLOSE")

        close_packet = pack_packet(
            TYPE_CLOSE,
            0,
            b"close",
        )

        try:
            sock.sendto(
                close_packet,
                server_addr,
            )

            sock.settimeout(2)

            close_response, addr = sock.recvfrom(65535)

            if addr == server_addr:
                packet_type, sequence, payload = unpack_packet(
                    close_response
                )

                if (
                    packet_type == TYPE_CLOSE
                    and sequence == 0
                    and payload == b"close"
                ):
                    print("[CLOSE] Server CLOSE received")

        except Exception as e:
            print("[CLOSE] Close response not confirmed:", e)

        print("[STATE] CLOSED")

    finally:
        os.close(tun_fd)
        sock.close()

        print("[TUN] tjvpn0 closed")
        print("[INFO] Stage 5 client stopped")


if __name__ == "__main__":
    main()
