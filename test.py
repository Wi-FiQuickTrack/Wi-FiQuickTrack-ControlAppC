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
        raw += bytearray(self.val)
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
    hexstring = ""
    for b in bytearray(input):
        hexstring += "0x%02x " % b
    return hexstring.rstrip()

def send_indigo_api(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (ip, port)

    for output in outputs:
        try:
            # Send Requset
            print('sending request')
            sent = sock.sendto(output, server_address)

            # Receive ACK
            print('waiting to receive ack')
            data, server = sock.recvfrom(4096)
            print('received "%s"' % get_hexstring(data))

            # Receive Response
            print('waiting to receive response')
            data, server = sock.recvfrom(4096)
            print('received "%s"' % get_hexstring(data))
            print('(ascii)  "%s"' % (data))
            time.sleep(command_interval)
        except Exception as e:
            print(e)
            print("An exception occurred and closing socket")
            sock.close()
            break

    print("closing socket")
    sock.close()

def send_indigo_api_raw(ip, port, raw):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (ip, port)

    try:
        # Send Requset
        print('sending request')
        sent = sock.sendto(raw, server_address)

        # Receive ACK
        print('waiting to receive ack')
        data, server = sock.recvfrom(4096)
        print('received "%s"' % get_hexstring(data))

        # Receive Response
        print('waiting to receive response')
        data, server = sock.recvfrom(4096)
        print('received "%s"' % get_hexstring(data))
        print('(ascii)  "%s"' % (data))
        time.sleep(command_interval)
    except Exception as e:
        print(e)
        print("An exception occurred and closing socket")
        sock.close()

    print("closing socket")
    sock.close()

def test_get_control_app():
    m = Msg(0x5002)
    return m

def test_loopback_start(lb_port=55501):
    m = Msg(0x5003)
    m.append_tlv(Tlv(0x0054, bytes(b'%d' % lb_port)))
    return m

def test_loopback_stop():
    m = Msg(0x5004)
    return m

def test_loopback_send_data():
    m = Msg(0x5008)
    m.append_tlv(Tlv(0x0058, bytes(b'10.252.10.32')))
    m.append_tlv(Tlv(0x0054, bytes(b'20480')))
    m.append_tlv(Tlv(0x0067, bytes(b'12')))
    m.append_tlv(Tlv(0x0069, bytes(b'1')))
    m.append_tlv(Tlv(0x00c0, bytes(b'1200')))
    return m

def start_loopback_client(target_host, target_port=20480, count=10, size=1000):
    recv_count = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (target_host, target_port)
    
    letters = string.ascii_lowercase

    for i in range(count):
        loopback_data = ''.join(random.choice(letters) for i in range(size))
        try:
            # Send Requset
            print('[count=%d] sending loopback data len=%d %s...' % (i, len(loopback_data), loopback_data[0:50]))
            sent = sock.sendto(loopback_data, server_address)

            # Receive Response
            data, server = sock.recvfrom(4096)
            print('[count=%d] received loopback data len=%d %s...' % (i, len(data), data[0:50]))
            recv_count = recv_count + 1
        except:
            print("[count=%d] failed to send socket")

    sock.close()
    print("Percentage: %d%%" % int((float(recv_count)/float(count))*100) )


def test_ap_send_disassociate():
    m = Msg(0x1004)
    m.append_tlv(Tlv(0x0028, bytes(b'b8:5d:0a:62:b3:ee')))
    return m

def test_sta_start_up():
    m = Msg(0x2008)
    m.append_tlv(Tlv(0x0097, bytes(b'udp:10240')))
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

def test_sta_disconnect():
    m = Msg(0x2002)
    return m

def test_ap_start():
    m = Msg(0x1000)
    return m

def test_ap_stop():
    m = Msg(0x1001)
    return m

def test_get_mac_addr():
    m = Msg(0x5001)
    return m

def test_ap_configure():
    # Bytes to DUT : 01 10 02 01 51 ff ff 00 01 11 49 6e 64 69 67 6f 5f 31 36 30 32 38 33 39 35 39 34
    #                00 07 01 31
    #                00 02 02 31 31
    #                00 1e 01 67
    #                00 0e 20 30 31 32 33 34 35 36 37 38 39 61 62 63 64 65 66 30 31 32 33 34 35 36 37 38 39 61 62 63 64 65 66
    #                00 0b 01 32 
    #                00 0c 03 53 41 45 
    #                00 0d 04 43 43 4d 50
    m = Msg(0x1002)
    m.append_tlv(Tlv(0x0001, bytes(b'Indigo_1602839594')))
    m.append_tlv(Tlv(0x0007, bytes(b'1')))
    m.append_tlv(Tlv(0x0002, bytes(b'11')))
    m.append_tlv(Tlv(0x001e, bytes(b'g')))
    m.append_tlv(Tlv(0x000e, bytes(b'0123456789abcdef0123456789abcdef')))
    m.append_tlv(Tlv(0x000b, bytes(b'2')))
    m.append_tlv(Tlv(0x000c, bytes(b'SAE')))
    m.append_tlv(Tlv(0x000d, bytes(b'CCMP')))
#    m.append_tlv(Tlv(0x000d, [0x43, 0x43, 0x4d, 0x50] ))
    return m

def test_assign_static_ip():
    # Bytes to DUT : 01 50 06 00 cc ff ff 00 55 0b 31 39 32 2e 31 36 38 2e 31 2e 31
    m = Msg(0x5006)
    m.append_tlv(Tlv(0x0055, bytes(b'192.168.1.1')))
    return m

def test_device_reset():
    # REQ: 01 50 07 01 4f ff ff 00 5c 01 32 00 57 01 30
    # RSP: 01 00 01 01 4f ff ff a0 01 01 30 a0 00 15 41 43 4b 3a 20 43 6f 6d 6d 61 6e 64 20 72 65 63 65 69 76 65 64
    m = Msg(0x5007)
    m.append_tlv(Tlv(0x005c, bytes(0x32)))
    m.append_tlv(Tlv(0x0057, bytes(0x30)))
    return m

def test_hex_file(ip, port, fn):
    raw = bytearray()
    f = open(fn, "r")
    txt = f.read()
    data = txt.split(", ")
    for d in data:
        hex_int = int(d, 16)
        raw.append(hex_int & 0x00ff)
    send_indigo_api_raw(ip, port, raw)

command_interval = 1
outputs = []

# ContrlAppC ip and port
peer_ip = '10.252.10.139'
peer_port = 9004

if len(sys.argv) == 1:
    m = test_get_control_app()
    outputs.append(m.to_bytes())
elif len(sys.argv) >= 2:
    if sys.argv[1] == "get_control_app":
        m = test_get_control_app()
        outputs.append(m.to_bytes())
    elif sys.argv[1] == "loopback_start":
        if len(sys.argv) == 3:
            m = test_loopback_start(int(sys.argv[2]))
        else:
            m = test_loopback_start()
        outputs.append(m.to_bytes())
    elif sys.argv[1] == "loopback_test":
        start_loopback_client(peer_ip, 20480, 10, 1000)
        m = test_get_control_app()
        outputs.append(m.to_bytes())
    elif sys.argv[1] == "loopback_send_data":
        m = test_loopback_send_data()
        outputs.append(m.to_bytes())
    elif sys.argv[1] == "loopback_stop":
        m = test_loopback_stop()
        outputs.append(m.to_bytes())
    elif sys.argv[1] == "device_reset":
        m = test_device_reset()
        outputs.append(m.to_bytes())
    elif sys.argv[1] == "ap_start":
        m = test_ap_start()
        outputs.append(m.to_bytes())
    elif sys.argv[1] == "ap_stop":
        m = test_ap_stop()
        outputs.append(m.to_bytes())
    elif sys.argv[1] == "ap_configure":
        m = test_ap_configure()
        outputs.append(m.to_bytes())
    elif sys.argv[1] == "sta_start_up":
        m = test_sta_start_up()
        outputs.append(m.to_bytes())
    elif sys.argv[1] == "sta_disconnect":
        m = test_sta_disconnect()
        outputs.append(m.to_bytes())
    elif sys.argv[1] == "assign_static_ip":
        m = test_assign_static_ip()
    elif sys.argv[1] == "get_mac_addr":
        m = test_get_mac_addr()
        outputs.append(m.to_bytes())
    elif sys.argv[1] == "file":
        test_hex_file(peer_ip, peer_port, sys.argv[2])
        sys.exit()
    else:
        m = test_get_control_app()
        outputs.append(m.to_bytes())

send_indigo_api(peer_ip, peer_port)
