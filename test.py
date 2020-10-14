import random, socket, sys

class Tlv():
    def __init__(self, id, val):
        self.id = id
        self.val = val
    def to_bytes(self):
        raw = bytearray()
        raw.append(self.id >> 8)
        raw.append(self.id & 0x00ff)
        raw.append(len(self.val))
        raw += bytes(self.val)
        return raw

class Msg():
    version = 0x01
    reserved = 0xff
    def __init__(self, id):
        self.id = id
        self.seq = random.randint(0x0000, 0xffff)
        self.tlvs = []
    def append_tlv(self, tlv):
        self.tlvs.append(tlv)
    def to_bytes(self):
        raw = bytearray()
        raw.append(self.version)
        raw.append(self.id >> 8)
        raw.append(self.id & 0x00ff)
        raw.append(self.seq >> 8)
        raw.append(self.seq & 0x00ff)
        raw.append(self.reserved)
        raw.append(self.reserved)
        for t in self.tlvs:
            output = t.to_bytes()
            raw += output

        return raw

def test_get_control_app():
    m = Msg(0x5002)
    return m

def test_loopback_start():
    m = Msg(0x5003)
    m.append_tlv(Tlv(0x0053, bytes(b'10.252.10.100')))
    m.append_tlv(Tlv(0x0054, bytes(b'20480')))
    return m

#m = test_get_control_app()
m = test_loopback_start()
output = m.to_bytes()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('10.252.10.100', 9004)

try:
    # Send Requset
    print >>sys.stderr, 'sending request'
    sent = sock.sendto(output, server_address)

    # Receive ACK
    print >>sys.stderr, 'waiting to receive ack'
    data, server = sock.recvfrom(4096)
    print >>sys.stderr, 'received "%s"' % data

    # Receive Response
    print >>sys.stderr, 'waiting to receive response'
    data, server = sock.recvfrom(4096)
    print >>sys.stderr, 'received "%s"' % data

finally:
    print >>sys.stderr, 'closing socket'
    sock.close()

