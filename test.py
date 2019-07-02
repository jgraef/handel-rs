import socket
import struct


class Message:
    def __init__(self, s):
        self.s = s

    def length(self):
        return len(self.s) + 1

    def encode(self):
        return struct.pack(">HB", self.length(), len(self.s)) + self.s.encode()


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
msg = Message("Hello World")
sock.sendto(msg.encode(), ("localhost", 12000))
