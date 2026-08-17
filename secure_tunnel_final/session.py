import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from protocol import (
    TYPE_DATA,
    pack_packet,
    unpack_packet,
)


IV_SIZE = 12
TAG_SIZE = 16


class ReplayError(Exception):
    pass


class DataAuthenticationError(Exception):
    pass


def encrypt_data(session_key, sequence, plaintext):
    if not 1 <= sequence <= 0xFFFFFFFF:
        raise ValueError("invalid DATA sequence number")

    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")

    iv = os.urandom(IV_SIZE)

    aesgcm = AESGCM(session_key)

    # cryptography 返回：
    # Ciphertext || 16-byte Auth Tag
    encrypted = aesgcm.encrypt(
        iv,
        plaintext,
        None,
    )

    ciphertext = encrypted[:-TAG_SIZE]
    auth_tag = encrypted[-TAG_SIZE:]

    payload = iv + encrypted

    packet = pack_packet(
        TYPE_DATA,
        sequence,
        payload,
    )

    return {
        "packet": packet,
        "sequence": sequence,
        "iv": iv,
        "plaintext": plaintext,
        "ciphertext": ciphertext,
        "auth_tag": auth_tag,
    }


def decrypt_data(session_key, packet, last_received_sequence):
    packet_type, sequence, payload = unpack_packet(
        packet
    )

    if packet_type != TYPE_DATA:
        raise ValueError("expected DATA packet")

    # 最低实现：严格递增
    if sequence <= last_received_sequence:
        raise ReplayError(
            f"replayed or old sequence number: {sequence}"
        )

    if len(payload) < IV_SIZE + TAG_SIZE:
        raise ValueError("DATA payload too short")

    iv = payload[:IV_SIZE]
    encrypted = payload[IV_SIZE:]

    ciphertext = encrypted[:-TAG_SIZE]
    auth_tag = encrypted[-TAG_SIZE:]

    aesgcm = AESGCM(session_key)

    try:
        plaintext = aesgcm.decrypt(
            iv,
            encrypted,
            None,
        )
    except InvalidTag as e:
        raise DataAuthenticationError(
            "AES-GCM authentication failed"
        ) from e

    # 注意：
    # 只有 AES-GCM 认证成功以后，调用方才能把
    # last_received_sequence 更新为这里返回的 sequence。

    return {
        "sequence": sequence,
        "iv": iv,
        "plaintext": plaintext,
        "ciphertext": ciphertext,
        "auth_tag": auth_tag,
    }
