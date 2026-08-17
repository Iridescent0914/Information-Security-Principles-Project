import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


print("=== Generate AES-128 Session Key ===")

session_key = AESGCM.generate_key(bit_length=128)

print("Session Key length =", len(session_key))
print("Session Key =", session_key.hex())

assert len(session_key) == 16


print("\n=== Encrypt ===")

aesgcm = AESGCM(session_key)

# AES-GCM 推荐使用 12 字节 IV / Nonce
iv = os.urandom(12)

plaintext = b"hello secure tunnel"

# 课程要求没有强制 AAD，本项目最低实现暂不使用 AAD
encrypted = aesgcm.encrypt(
    iv,
    plaintext,
    None,
)

# cryptography 返回：
# Ciphertext || 16-byte Auth Tag
ciphertext = encrypted[:-16]
auth_tag = encrypted[-16:]

payload = iv + ciphertext + auth_tag

print("Plaintext =", plaintext)
print("Plaintext length =", len(plaintext))

print("IV =", iv.hex())
print("IV length =", len(iv))

print("Ciphertext =", ciphertext.hex())
print("Ciphertext length =", len(ciphertext))

print("Auth Tag =", auth_tag.hex())
print("Auth Tag length =", len(auth_tag))

print("Payload =", payload.hex())
print("Payload length =", len(payload))

assert len(iv) == 12
assert len(auth_tag) == 16
assert len(ciphertext) == len(plaintext)

print("[PASS] AES-128-GCM encryption")


print("\n=== Decrypt ===")

received_iv = payload[:12]
received_ciphertext_and_tag = payload[12:]

decrypted = aesgcm.decrypt(
    received_iv,
    received_ciphertext_and_tag,
    None,
)

print("Decrypted =", decrypted)

assert decrypted == plaintext

print("[PASS] AES-128-GCM decryption")


print("\n=== Tamper ciphertext ===")

tampered_ciphertext = bytearray(ciphertext)
tampered_ciphertext[0] ^= 0x01

tampered_data = bytes(tampered_ciphertext) + auth_tag

try:
    aesgcm.decrypt(
        iv,
        tampered_data,
        None,
    )
except InvalidTag:
    print("[PASS] Modified ciphertext rejected: InvalidTag")
else:
    raise AssertionError("modified ciphertext should be rejected")


print("\n=== Tamper Auth Tag ===")

tampered_tag = bytearray(auth_tag)
tampered_tag[-1] ^= 0x01

tampered_data = ciphertext + bytes(tampered_tag)

try:
    aesgcm.decrypt(
        iv,
        tampered_data,
        None,
    )
except InvalidTag:
    print("[PASS] Modified Auth Tag rejected: InvalidTag")
else:
    raise AssertionError("modified Auth Tag should be rejected")


print("\n=== Wrong key test ===")

wrong_key = AESGCM.generate_key(bit_length=128)
wrong_aesgcm = AESGCM(wrong_key)

try:
    wrong_aesgcm.decrypt(
        iv,
        encrypted,
        None,
    )
except InvalidTag:
    print("[PASS] Wrong key rejected: InvalidTag")
else:
    raise AssertionError("wrong key should be rejected")


print("\nALL AES-GCM TESTS PASSED")
