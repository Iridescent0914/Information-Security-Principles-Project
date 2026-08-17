import struct

PCAP_FILE = "pcap/03_handshake.pcap"

SUBTYPES = {
    0x01: "ClientHello",
    0x02: "ServerHello",
    0x03: "ClientKeyExchange",
    0x04: "ServerKeyExchange",
    0x05: "ClientFinished",
    0x06: "ServerFinished",
}


def ip_to_str(data):
    return ".".join(str(x) for x in data)


with open(PCAP_FILE, "rb") as f:
    global_header = f.read(24)

    magic = global_header[:4]

    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise ValueError("unsupported pcap format")

    index = 0

    while True:
        packet_header = f.read(16)

        if not packet_header:
            break

        if len(packet_header) != 16:
            raise ValueError("truncated pcap header")

        _, _, captured_len, _ = struct.unpack(
            endian + "IIII",
            packet_header,
        )

        packet = f.read(captured_len)

        index += 1

        # 当前 pcap 的 link-type 是 RAW，因此 packet 直接从 IPv4 头开始。
        ihl = (packet[0] & 0x0F) * 4

        src_ip = ip_to_str(packet[12:16])
        dst_ip = ip_to_str(packet[16:20])

        udp = packet[ihl:]

        src_port, dst_port, udp_len, _ = struct.unpack(
            "!HHHH",
            udp[:8],
        )

        payload = udp[8:]

        if len(payload) < 10:
            raise ValueError("TJVPN packet too short")

        magic_number = payload[0:2]
        packet_type = payload[2]
        sequence = int.from_bytes(payload[3:7], "big")
        payload_length = int.from_bytes(payload[7:9], "big")
        subtype = payload[9]

        print(
            f"{index}: "
            f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
            f"Magic={magic_number.decode(errors='replace')} | "
            f"Type=0x{packet_type:02x} | "
            f"Seq={sequence} | "
            f"Length={payload_length} | "
            f"Subtype=0x{subtype:02x} "
            f"({SUBTYPES.get(subtype, 'Unknown')})"
        )
