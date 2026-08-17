import socket

SERVER_IP = "172.29.255.229"
SERVER_PORT = 2026

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)

message = b"hello udp"

print(f"Sending {message!r} to {SERVER_IP}:{SERVER_PORT}")
sock.sendto(message, (SERVER_IP, SERVER_PORT))

data, addr = sock.recvfrom(4096)
print(f"Received {data!r} from {addr}")
