from protocol import (
    MAGIC,
    HEADER_SIZE,
    TYPE_HANDSHAKE,
    TYPE_DATA,
    TYPE_CLOSE,
    pack_packet,
    unpack_packet,
)


def expect_error(name, func):
    try:
        func()
    except ValueError as e:
        print(f"[PASS] {name}: {e}")
    else:
        raise AssertionError(f"{name}: expected ValueError")


print("=== Basic constants ===")
print("MAGIC =", MAGIC)
print("HEADER_SIZE =", HEADER_SIZE)

assert MAGIC == b"TJ"
assert HEADER_SIZE == 9

print("\n=== Normal HANDSHAKE packet ===")

payload = b"hello"

# HANDSHAKE 按项目统一约定使用 sequence = 0
packet = pack_packet(TYPE_HANDSHAKE, 0, payload)

print("packet length =", len(packet))
print("packet hex    =", packet.hex())

packet_type, sequence, decoded_payload = unpack_packet(packet)

print("packet type   =", hex(packet_type))
print("sequence      =", sequence)
print("payload       =", decoded_payload)

assert packet_type == TYPE_HANDSHAKE
assert sequence == 0
assert decoded_payload == b"hello"

print("[PASS] encode/decode")


print("\n=== DATA packet ===")

data_packet = pack_packet(TYPE_DATA, 1, b"test-data")
ptype, seq, data = unpack_packet(data_packet)

print("packet type   =", hex(ptype))
print("sequence      =", seq)
print("payload       =", data)

assert ptype == TYPE_DATA
assert seq == 1
assert data == b"test-data"

print("[PASS] DATA packet")


print("\n=== CLOSE packet ===")

close_packet = pack_packet(TYPE_CLOSE, 0, b"close")
ptype, seq, data = unpack_packet(close_packet)

assert ptype == TYPE_CLOSE
assert seq == 0
assert data == b"close"

print("[PASS] CLOSE packet")


print("\n=== Invalid packet tests ===")

# 1. 错误 Magic
bad_magic = bytearray(packet)
bad_magic[0:2] = b"XX"

expect_error(
    "invalid magic",
    lambda: unpack_packet(bytes(bad_magic)),
)


# 2. 错误 Payload Length
# 固定头中 Payload Length 位于第 7、8 字节
bad_length = bytearray(packet)
bad_length[7:9] = (6).to_bytes(2, "big")

expect_error(
    "payload length mismatch",
    lambda: unpack_packet(bytes(bad_length)),
)


# 3. 删除最后一个字节
truncated = packet[:-1]

expect_error(
    "truncated packet",
    lambda: unpack_packet(truncated),
)


# 4. 非法 Packet Type
bad_type = bytearray(packet)
bad_type[2] = 0x99

expect_error(
    "invalid packet type",
    lambda: unpack_packet(bytes(bad_type)),
)


# 5. Sequence Number 超出 32 位
expect_error(
    "sequence too large",
    lambda: pack_packet(TYPE_DATA, 0x100000000, b"x"),
)


# 6. Sequence Number 为负数
expect_error(
    "negative sequence",
    lambda: pack_packet(TYPE_DATA, -1, b"x"),
)


print("\nALL PROTOCOL TESTS PASSED")
