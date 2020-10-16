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

def test_ap_send_disassociate():
    m = Msg(0x1004)
    m.append_tlv(Tlv(0x0028, bytes(b'b8:5d:0a:62:b3:ee')))
    return m

def test_sta_configure():
    m = Msg(0x2001)
    m.append_tlv(Tlv(0x0035, bytes(b'Indigo_1600155580'))) # SSID
    m.append_tlv(Tlv(0x003a, bytes(b'12345678'))) # PSK
    m.append_tlv(Tlv(0x003b, bytes(b'RSN'))) # PROTO
    m.append_tlv(Tlv(0x003d, bytes(b'CCMP'))) # PAIRWISE
    m.append_tlv(Tlv(0x003c, bytes(b'1'))) # STA_IEEE80211_W
    m.append_tlv(Tlv(0x0036, bytes(b'WPA-PSK'))) # KEY_MGMT
    return m

def test_sta_associate():
    m = Msg(0x2000)
    return m

def test_ap_start():
    m = Msg(0x1000)
    return m

#m = test_get_control_app()
#m = test_loopback_start()
#m = test_ap_send_disassociate()
#m = test_sta_configure()
# m = test_sta_associate()
m = test_ap_start()
output = m.to_bytes()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('10.252.10.47', 9002)

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

