import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def generate_ecdh_keypair():
    private_key = ec.generate_private_key(
        ec.SECP256R1()
    )

    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

    return private_key, public_key_bytes


def load_ecdh_public_key(public_key_bytes):
    return ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        public_key_bytes,
    )


def compute_pre_master(private_key, peer_public_bytes):
    peer_public_key = load_ecdh_public_key(
        peer_public_bytes
    )

    return private_key.exchange(
        ec.ECDH(),
        peer_public_key,
    )


def compute_transcript_hash(*messages):
    return hashlib.sha256(
        b"".join(messages)
    ).digest()


def derive_session_key(
    pre_master,
    client_random,
    server_random,
    transcript_hash,
):
    # 按当前课程最低实现：
    # Pre-Master + Client Random + Server Random
    # + Handshake Transcript Hash
    ikm = (
        pre_master
        + client_random
        + server_random
        + transcript_hash
    )

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b"TJVPN-2026-session-key",
    )

    return hkdf.derive(ikm)


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()

import hmac


def compute_finished(session_key, transcript_hash):
    return hmac.new(
        session_key,
        transcript_hash,
        hashlib.sha256,
    ).digest()


def verify_finished(session_key, transcript_hash, received):
    expected = compute_finished(
        session_key,
        transcript_hash,
    )

    return hmac.compare_digest(
        expected,
        received,
    )
