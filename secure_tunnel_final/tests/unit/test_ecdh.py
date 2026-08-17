import hashlib

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


print("=== Generate ephemeral ECDH keys ===")

client_private = ec.generate_private_key(ec.SECP256R1())
server_private = ec.generate_private_key(ec.SECP256R1())

client_public = client_private.public_key()
server_public = server_private.public_key()

print("Client private key: generated")
print("Server private key: generated")


print("\n=== Serialize public keys ===")

client_public_bytes = client_public.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint,
)

server_public_bytes = server_public.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint,
)

print("Client public key length =", len(client_public_bytes))
print("Server public key length =", len(server_public_bytes))

print("Client public key prefix =", hex(client_public_bytes[0]))
print("Server public key prefix =", hex(server_public_bytes[0]))

assert len(client_public_bytes) == 65
assert len(server_public_bytes) == 65
assert client_public_bytes[0] == 0x04
assert server_public_bytes[0] == 0x04

print("[PASS] X9.62 uncompressed public key encoding")


print("\n=== Parse peer public keys ===")

client_peer_public = ec.EllipticCurvePublicKey.from_encoded_point(
    ec.SECP256R1(),
    server_public_bytes,
)

server_peer_public = ec.EllipticCurvePublicKey.from_encoded_point(
    ec.SECP256R1(),
    client_public_bytes,
)

print("[PASS] public key parsing")


print("\n=== ECDH key exchange ===")

client_shared = client_private.exchange(
    ec.ECDH(),
    client_peer_public,
)

server_shared = server_private.exchange(
    ec.ECDH(),
    server_peer_public,
)

client_hash = hashlib.sha256(client_shared).hexdigest()
server_hash = hashlib.sha256(server_shared).hexdigest()

print("Client Pre-Master length =", len(client_shared))
print("Server Pre-Master length =", len(server_shared))

print("Client Pre-Master SHA256 =", client_hash)
print("Server Pre-Master SHA256 =", server_hash)

assert client_shared == server_shared
assert client_hash == server_hash

print("[PASS] ECDH Pre-Master Secret is identical")


print("\n=== Invalid public key test ===")

bad_public_key = bytearray(client_public_bytes)
bad_public_key[0] = 0x05

try:
    ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        bytes(bad_public_key),
    )
except ValueError as e:
    print("[PASS] invalid public key rejected:", e)
else:
    raise AssertionError("invalid public key should have been rejected")


print("\nALL ECDH TESTS PASSED")
