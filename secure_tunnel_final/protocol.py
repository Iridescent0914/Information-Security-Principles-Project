import struct

MAGIC = b"TJ"

TYPE_HANDSHAKE = 0x01
TYPE_DATA = 0x02
TYPE_CLOSE = 0x03

HEADER_FORMAT = "!2sBIH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


def pack_packet(packet_type: int, sequence: int, payload: bytes) -> bytes:
    if packet_type not in (TYPE_HANDSHAKE, TYPE_DATA, TYPE_CLOSE):
        raise ValueError("invalid packet type")

    if not 0 <= sequence <= 0xFFFFFFFF:
        raise ValueError("invalid sequence number")

    if len(payload) > 0xFFFF:
        raise ValueError("payload too long")

    header = struct.pack(
        HEADER_FORMAT,
        MAGIC,
        packet_type,
        sequence,
        len(payload),
    )

    return header + payload


def unpack_packet(data: bytes):
    if len(data) < HEADER_SIZE:
        raise ValueError("packet too short")

    magic, packet_type, sequence, payload_length = struct.unpack(
        HEADER_FORMAT,
        data[:HEADER_SIZE],
    )

    if magic != MAGIC:
        raise ValueError("invalid magic")

    if packet_type not in (TYPE_HANDSHAKE, TYPE_DATA, TYPE_CLOSE):
        raise ValueError("invalid packet type")

    payload = data[HEADER_SIZE:]

    if len(payload) != payload_length:
        raise ValueError("payload length mismatch")

    return packet_type, sequence, payload

# Handshake subtypes
HS_CLIENT_HELLO = 0x01
HS_SERVER_HELLO = 0x02
HS_CLIENT_KEY_EXCHANGE = 0x03
HS_SERVER_KEY_EXCHANGE = 0x04
HS_CLIENT_FINISHED = 0x05
HS_SERVER_FINISHED = 0x06
