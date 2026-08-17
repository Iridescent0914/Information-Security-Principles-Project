import os
import fcntl
import struct


TUNSETIFF = 0x400454CA

IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

TUN_NAME = "tjvpn0"


def create_tun(name=TUN_NAME):
    """
    Create a Layer-3 TUN device.

    Returns:
        (tun_fd, actual_name)
    """
    tun_fd = os.open("/dev/net/tun", os.O_RDWR)

    ifreq = struct.pack(
        "16sH",
        name.encode("ascii"),
        IFF_TUN | IFF_NO_PI,
    )

    result = fcntl.ioctl(
        tun_fd,
        TUNSETIFF,
        ifreq,
    )

    actual_name = result[:16].split(b"\x00", 1)[0].decode("ascii")

    return tun_fd, actual_name
