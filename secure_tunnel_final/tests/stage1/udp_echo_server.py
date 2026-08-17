import socket

HOST = "0.0.0.0"
PORT = 2026

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

print(f"UDP server listening on {HOST}:{PORT}")

while True:
    data, addr = sock.recvfrom(4096)
    print(f"Received {data!r} from {addr}")
    sock.sendto(b"echo:" + data, addr)
