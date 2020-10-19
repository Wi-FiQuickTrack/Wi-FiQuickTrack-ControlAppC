import random, socket, string, sys, time

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

def get_hexstring(input):
    return ("".join("0x{:02x} ".format(ord(c)) for c in input)).rstrip()

def send_indigo_api(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (ip, port)

    for output in outputs:
        try:
            # Send Requset
            print >>sys.stderr, 'sending request'
            sent = sock.sendto(output, server_address)

            # Receive ACK
            print >>sys.stderr, 'waiting to receive ack'
            data, server = sock.recvfrom(4096)
            print >>sys.stderr, 'received "%s"' % get_hexstring(data)

            # Receive Response
            print >>sys.stderr, 'waiting to receive response'
            data, server = sock.recvfrom(4096)
            print >>sys.stderr, 'received "%s"' % get_hexstring(data)
            time.sleep(command_interval)
        except:
            print("An exception occurred and closing socket")
            sock.close()
            break

    print("closing socket")
    sock.close()


def test_get_control_app():
    m = Msg(0x5002)
    return m

def test_loopback_start():
    m = Msg(0x5003)
    m.append_tlv(Tlv(0x0053, bytes(b'10.252.10.100')))
    m.append_tlv(Tlv(0x0054, bytes(b'20480')))
    return m

def test_loopback_stop():
    m = Msg(0x5004)
    return m

def start_loopback_client(target_host='10.252.10.47', target_port=20480, count=10, size=1000):
    recv_count = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (target_host, target_port)
    
    letters = string.ascii_lowercase

    for i in range(count):
        loopback_data = ''.join(random.choice(letters) for i in range(size))
        try:
            # Send Requset
            print >>sys.stderr, '[count=%d] sending loopback data len=%d %s...' % (i, len(loopback_data), loopback_data[0:50])
            sent = sock.sendto(loopback_data, server_address)

            # Receive Response
            data, server = sock.recvfrom(4096)
            print >>sys.stderr, '[count=%d] received loopback data len=%d %s...' % (i, len(data), data[0:50])
            recv_count = recv_count + 1
        except:
            print("[count=%d] failed to send socket")

    sock.close()
    print("Percentage: %d%%" % int((float(recv_count)/float(count))*100) )


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

command_interval = 1
outputs = []

if len(sys.argv) == 1:
    m = test_get_control_app()
    outputs.append(m.to_bytes())
elif len(sys.argv) >= 2:
    if sys.argv[1] == "get_control_app":
        m = test_get_control_app()
        outputs.append(m.to_bytes())
    elif sys.argv[1] == "loopback_start":
        m = test_loopback_start()
        outputs.append(m.to_bytes())
    elif sys.argv[1] == "loopback_test":
        start_loopback_client('10.252.10.47', 20480, 10, 1000)
        m = test_get_control_app()
        outputs.append(m.to_bytes())
    elif sys.argv[1] == "loopback_stop":
        m = test_loopback_stop()
        outputs.append(m.to_bytes())
    else:

send_indigo_api('10.252.10.47', 9004)
