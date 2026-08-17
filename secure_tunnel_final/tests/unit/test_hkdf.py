import os
import hashlib

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def derive_session_key(pre_master, client_random, server_random, transcript_hash):
    # 按课程要求：
    # Pre-Master + Client Random + Server Random + Handshake Hash
    ikm = (
        pre_master
        + client_random
        + server_random
        + transcript_hash
    )

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=16,          # AES-128 Session Key
        salt=None,
        info=b"TJVPN-2026-session-key",
    )

    return hkdf.derive(ikm)


print("=== Generate ECDH keys ===")

client_private = ec.generate_private_key(ec.SECP256R1())
server_private = ec.generate_private_key(ec.SECP256R1())

client_shared = client_private.exchange(
    ec.ECDH(),
    server_private.public_key(),
)

server_shared = server_private.exchange(
    ec.ECDH(),
    client_private.public_key(),
)

assert client_shared == server_shared

print("Pre-Master length =", len(client_shared))
print(
    "Pre-Master SHA256 =",
    hashlib.sha256(client_shared).hexdigest(),
)


print("\n=== Generate randoms ===")

client_random = os.urandom(16)
server_random = os.urandom(16)

print("Client Random length =", len(client_random))
print("Server Random length =", len(server_random))

print("Client Random =", client_random.hex())
print("Server Random =", server_random.hex())


print("\n=== Build simulated handshake transcript ===")

client_hello = b"\x01ClientHello"
server_hello = b"\x02ServerHello"
client_key_exchange = b"\x03ClientKeyExchange"
server_key_exchange = b"\x04ServerKeyExchange"

transcript = (
    client_hello
    + server_hello
    + client_key_exchange
    + server_key_exchange
)

transcript_hash = hashlib.sha256(transcript).digest()

print("Transcript length =", len(transcript))
print("Transcript SHA256 =", transcript_hash.hex())


print("\n=== HKDF-SHA256 ===")

client_session_key = derive_session_key(
    client_shared,
    client_random,
    server_random,
    transcript_hash,
)

server_session_key = derive_session_key(
    server_shared,
    client_random,
    server_random,
    transcript_hash,
)

print("Client Session Key length =", len(client_session_key))
print("Server Session Key length =", len(server_session_key))

print("Client Session Key =", client_session_key.hex())
print("Server Session Key =", server_session_key.hex())

print(
    "Client Session Key SHA256 =",
    hashlib.sha256(client_session_key).hexdigest(),
)

print(
    "Server Session Key SHA256 =",
    hashlib.sha256(server_session_key).hexdigest(),
)

assert client_session_key == server_session_key
assert len(client_session_key) == 16

print("[PASS] Client and Server Session Keys are identical")


print("\n=== Modified transcript test ===")

modified_transcript_hash = hashlib.sha256(
    transcript + b"modified"
).digest()

modified_session_key = derive_session_key(
    client_shared,
    client_random,
    server_random,
    modified_transcript_hash,
)

assert modified_session_key != client_session_key

print("[PASS] Modified transcript produces a different Session Key")


print("\nALL HKDF TESTS PASSED")
