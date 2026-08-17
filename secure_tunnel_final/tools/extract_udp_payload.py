import struct
import sys
from pathlib import Path


if len(sys.argv) != 3:
    print(
        f"Usage: {sys.argv[0]} "
        "<input.pcap> <output.txt>"
    )
    raise SystemExit(1)


pcap_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])

raw = pcap_path.read_bytes()

if len(raw) < 24:
    raise ValueError("pcap too short")

magic = raw[:4]

if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
    endian = "<"
elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
    endian = ">"
else:
    raise ValueError(
        "unsupported pcap format or pcapng"
    )

offset = 24

if len(raw) < offset + 16:
    raise ValueError("no packet in pcap")

ts_sec, ts_frac, incl_len, orig_len = struct.unpack(
    endian + "IIII",
    raw[offset:offset + 16],
)

offset += 16

packet = raw[offset:offset + incl_len]

if len(packet) != incl_len:
    raise ValueError("truncated packet")

# VMware tun0 抓包 link type = RAW，
# 所以 packet 第一个字节就是外层 IPv4 Header。
version = packet[0] >> 4

if version != 4:
    raise ValueError(
        f"expected outer IPv4, got version {version}"
    )

ihl = (packet[0] & 0x0F) * 4

if packet[9] != 17:
    raise ValueError("outer packet is not UDP")

udp_offset = ihl

src_port, dst_port, udp_len, checksum = struct.unpack(
    "!HHHH",
    packet[udp_offset:udp_offset + 8],
)

payload = packet[
    udp_offset + 8:
    udp_offset + udp_len
]

output_path.write_text(
    payload.hex() + "\n"
)

print("[PASS] UDP payload extracted")
print("src_port =", src_port)
print("dst_port =", dst_port)
print("udp_length =", udp_len)
print("payload_length =", len(payload))
print("payload =", payload.hex())
