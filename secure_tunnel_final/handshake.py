import struct

from protocol import (
    HS_CLIENT_HELLO,
    HS_SERVER_HELLO,
    HS_CLIENT_KEY_EXCHANGE,
    HS_SERVER_KEY_EXCHANGE,
    HS_CLIENT_FINISHED,
    HS_SERVER_FINISHED,
)


PROTOCOL_VERSION = 0x0001

# 当前最低实现只支持一个密码套件
CIPHER_SUITE = 0x0001


# ============================================================
# ClientHello
#
# Subtype             1 byte
# Protocol Version     2 bytes
# Client Random       16 bytes
# Suite Count          1 byte
# Cipher Suites        2 * N bytes
# ============================================================

def pack_client_hello(client_random: bytes,
                      suites=(CIPHER_SUITE,)) -> bytes:
    if len(client_random) != 16:
        raise ValueError("client random must be 16 bytes")

    if not 1 <= len(suites) <= 255:
        raise ValueError("invalid suite count")

    for suite in suites:
        if not 0 <= suite <= 0xFFFF:
            raise ValueError("invalid cipher suite")

    payload = struct.pack(
        "!BH16sB",
        HS_CLIENT_HELLO,
        PROTOCOL_VERSION,
        client_random,
        len(suites),
    )

    for suite in suites:
        payload += struct.pack("!H", suite)

    return payload


def unpack_client_hello(payload: bytes):
    fixed_size = struct.calcsize("!BH16sB")

    if len(payload) < fixed_size:
        raise ValueError("ClientHello too short")

    subtype, version, client_random, suite_count = struct.unpack(
        "!BH16sB",
        payload[:fixed_size],
    )

    if subtype != HS_CLIENT_HELLO:
        raise ValueError("not ClientHello")

    expected_length = fixed_size + suite_count * 2

    if len(payload) != expected_length:
        raise ValueError("ClientHello length mismatch")

    suites = []

    offset = fixed_size

    for _ in range(suite_count):
        suite = struct.unpack(
            "!H",
            payload[offset:offset + 2],
        )[0]

        suites.append(suite)
        offset += 2

    return version, client_random, suites


# ============================================================
# ServerHello
#
# Subtype              1 byte
# Protocol Version      2 bytes
# Server Random        16 bytes
# Selected Suite        2 bytes
# Certificate Length    2 bytes
# Certificate           variable
# ============================================================

def pack_server_hello(server_random: bytes,
                      selected_suite: int,
                      certificate_pem: bytes) -> bytes:
    if len(server_random) != 16:
        raise ValueError("server random must be 16 bytes")

    if not 0 <= selected_suite <= 0xFFFF:
        raise ValueError("invalid selected suite")

    if len(certificate_pem) > 0xFFFF:
        raise ValueError("certificate too large")

    header = struct.pack(
        "!BH16sHH",
        HS_SERVER_HELLO,
        PROTOCOL_VERSION,
        server_random,
        selected_suite,
        len(certificate_pem),
    )

    return header + certificate_pem


def unpack_server_hello(payload: bytes):
    fixed_size = struct.calcsize("!BH16sHH")

    if len(payload) < fixed_size:
        raise ValueError("ServerHello too short")

    (
        subtype,
        version,
        server_random,
        selected_suite,
        cert_length,
    ) = struct.unpack(
        "!BH16sHH",
        payload[:fixed_size],
    )

    if subtype != HS_SERVER_HELLO:
        raise ValueError("not ServerHello")

    certificate_pem = payload[fixed_size:]

    if len(certificate_pem) != cert_length:
        raise ValueError("certificate length mismatch")

    return (
        version,
        server_random,
        selected_suite,
        certificate_pem,
    )


# ============================================================
# ClientKeyExchange / ServerKeyExchange
#
# Subtype             1 byte
# Public Key Length   2 bytes
# Public Key          variable
# ============================================================

def pack_key_exchange(subtype: int,
                      public_key: bytes) -> bytes:
    if subtype not in (
        HS_CLIENT_KEY_EXCHANGE,
        HS_SERVER_KEY_EXCHANGE,
    ):
        raise ValueError("invalid key exchange subtype")

    if len(public_key) > 0xFFFF:
        raise ValueError("public key too large")

    return (
        struct.pack("!BH", subtype, len(public_key))
        + public_key
    )


def unpack_key_exchange(payload: bytes,
                        expected_subtype: int) -> bytes:
    if len(payload) < 3:
        raise ValueError("KeyExchange too short")

    subtype, key_length = struct.unpack(
        "!BH",
        payload[:3],
    )

    if subtype != expected_subtype:
        raise ValueError("unexpected key exchange subtype")

    public_key = payload[3:]

    if len(public_key) != key_length:
        raise ValueError("public key length mismatch")

    return public_key


# ============================================================
# ClientFinished / ServerFinished
#
# Subtype              1 byte
# Verify Data Length    2 bytes
# Verify Data          32 bytes
# ============================================================

def pack_finished(subtype: int,
                  verify_data: bytes) -> bytes:
    if subtype not in (
        HS_CLIENT_FINISHED,
        HS_SERVER_FINISHED,
    ):
        raise ValueError("invalid Finished subtype")

    if len(verify_data) != 32:
        raise ValueError("Finished verify_data must be 32 bytes")

    return struct.pack(
        "!BH",
        subtype,
        len(verify_data),
    ) + verify_data


def unpack_finished(payload: bytes,
                    expected_subtype: int) -> bytes:
    if len(payload) < 3:
        raise ValueError("Finished too short")

    subtype, verify_length = struct.unpack(
        "!BH",
        payload[:3],
    )

    if subtype != expected_subtype:
        raise ValueError("unexpected Finished subtype")

    verify_data = payload[3:]

    if verify_length != 32:
        raise ValueError("invalid Finished length")

    if len(verify_data) != verify_length:
        raise ValueError("Finished length mismatch")

    return verify_data
