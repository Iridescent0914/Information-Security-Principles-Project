import os

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from protocol import (
    TYPE_HANDSHAKE,
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
    pack_client_hello,
    unpack_client_hello,
    pack_server_hello,
    unpack_server_hello,
    pack_key_exchange,
    unpack_key_exchange,
    pack_finished,
    unpack_finished,
)


print("=== ClientHello ===")

client_random = os.urandom(16)

client_hello = pack_client_hello(
    client_random,
    (CIPHER_SUITE,),
)

version, decoded_random, suites = unpack_client_hello(
    client_hello
)

print("ClientHello length =", len(client_hello))
print("Protocol Version =", hex(version))
print("Client Random =", client_random.hex())
print("Cipher Suites =", [hex(x) for x in suites])

assert version == PROTOCOL_VERSION
assert decoded_random == client_random
assert suites == [CIPHER_SUITE]

print("[PASS] ClientHello")


print("\n=== ServerHello ===")

with open("certs/server_cert.pem", "rb") as f:
    certificate_pem = f.read()

server_random = os.urandom(16)

server_hello = pack_server_hello(
    server_random,
    CIPHER_SUITE,
    certificate_pem,
)

(
    version,
    decoded_server_random,
    selected_suite,
    decoded_certificate,
) = unpack_server_hello(server_hello)

print("ServerHello length =", len(server_hello))
print("Protocol Version =", hex(version))
print("Server Random =", server_random.hex())
print("Selected Suite =", hex(selected_suite))
print("Certificate length =", len(decoded_certificate))

assert version == PROTOCOL_VERSION
assert decoded_server_random == server_random
assert selected_suite == CIPHER_SUITE
assert decoded_certificate == certificate_pem

print("[PASS] ServerHello")


print("\n=== KeyExchange ===")

client_private = ec.generate_private_key(ec.SECP256R1())
server_private = ec.generate_private_key(ec.SECP256R1())

client_public = client_private.public_key().public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint,
)

server_public = server_private.public_key().public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint,
)

client_key_exchange = pack_key_exchange(
    HS_CLIENT_KEY_EXCHANGE,
    client_public,
)

server_key_exchange = pack_key_exchange(
    HS_SERVER_KEY_EXCHANGE,
    server_public,
)

decoded_client_public = unpack_key_exchange(
    client_key_exchange,
    HS_CLIENT_KEY_EXCHANGE,
)

decoded_server_public = unpack_key_exchange(
    server_key_exchange,
    HS_SERVER_KEY_EXCHANGE,
)

print("Client public key length =", len(decoded_client_public))
print("Server public key length =", len(decoded_server_public))

assert decoded_client_public == client_public
assert decoded_server_public == server_public
assert len(client_public) == 65
assert len(server_public) == 65

print("[PASS] ClientKeyExchange")
print("[PASS] ServerKeyExchange")


print("\n=== Finished ===")

verify_data = os.urandom(32)

client_finished = pack_finished(
    HS_CLIENT_FINISHED,
    verify_data,
)

server_finished = pack_finished(
    HS_SERVER_FINISHED,
    verify_data,
)

assert unpack_finished(
    client_finished,
    HS_CLIENT_FINISHED,
) == verify_data

assert unpack_finished(
    server_finished,
    HS_SERVER_FINISHED,
) == verify_data

print("Finished verify_data length =", len(verify_data))

print("[PASS] ClientFinished")
print("[PASS] ServerFinished")


print("\n=== Outer protocol integration ===")

packet = pack_packet(
    TYPE_HANDSHAKE,
    0,
    client_hello,
)

packet_type, sequence, payload = unpack_packet(packet)

assert packet_type == TYPE_HANDSHAKE
assert sequence == 0
assert payload == client_hello

print("Outer packet length =", len(packet))
print("Outer Sequence Number =", sequence)

print("[PASS] 9-byte outer protocol integration")


print("\nALL HANDSHAKE MESSAGE TESTS PASSED")
