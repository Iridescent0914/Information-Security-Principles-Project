import hashlib
import hmac
import os


print("=== Prepare Session Key and Transcript ===")

session_key = os.urandom(16)

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

print("Session Key length =", len(session_key))
print("Transcript SHA256 =", transcript_hash.hex())


print("\n=== Client Finished ===")

client_finished = hmac.new(
    session_key,
    transcript_hash,
    hashlib.sha256,
).digest()

print("Client Finished length =", len(client_finished))
print("Client Finished =", client_finished.hex())

assert len(client_finished) == 32

expected_client_finished = hmac.new(
    session_key,
    transcript_hash,
    hashlib.sha256,
).digest()

assert hmac.compare_digest(
    client_finished,
    expected_client_finished,
)

print("[PASS] Client Finished verified")


print("\n=== Server Finished ===")

server_finished = hmac.new(
    session_key,
    transcript_hash,
    hashlib.sha256,
).digest()

print("Server Finished length =", len(server_finished))
print("Server Finished =", server_finished.hex())

assert hmac.compare_digest(
    server_finished,
    client_finished,
)

print("[PASS] Server Finished verified")


print("\n=== Modified transcript test ===")

modified_transcript_hash = hashlib.sha256(
    transcript + b"modified"
).digest()

wrong_finished = hmac.new(
    session_key,
    modified_transcript_hash,
    hashlib.sha256,
).digest()

if not hmac.compare_digest(
    client_finished,
    wrong_finished,
):
    print("[PASS] Modified transcript causes Finished verification failure")
else:
    raise AssertionError("modified transcript should fail")


print("\n=== Modified Finished test ===")

tampered_finished = bytearray(client_finished)
tampered_finished[0] ^= 0x01

if not hmac.compare_digest(
    client_finished,
    bytes(tampered_finished),
):
    print("[PASS] Modified Finished rejected")
else:
    raise AssertionError("modified Finished should fail")


print("\n=== Wrong Session Key test ===")

wrong_key = os.urandom(16)

wrong_key_finished = hmac.new(
    wrong_key,
    transcript_hash,
    hashlib.sha256,
).digest()

if not hmac.compare_digest(
    client_finished,
    wrong_key_finished,
):
    print("[PASS] Wrong Session Key causes Finished verification failure")
else:
    raise AssertionError("wrong Session Key should fail")


print("\nALL FINISHED TESTS PASSED")
