import threading
import time
from socket import *

class SeqAckChannelHandler:
    def __init__(self, connection, replyCid, service, upstreamHandler):
        self.replyCid = replyCid
        self.upstreamHandler = upstreamHandler
        self.sid = service
        self.connection = connection
        ackTimeout = threading.Thread(target=self.ackTimeout)
        ackTimeout.start()

    sent = 0
    received = 0
    acknowledged = 0

    def receive(self, handle, pdu):
        seq = pdu[0] >> 1
        ack = pdu[1]
        msg = pdu[2:]

        if len(msg) == 0:
            print(f"----- seqack received for sid {self.sid} special ack {ack}, time {time.time()}")
        else:
            self.received += 1
            #print(f"----- seqack received for sid {self.sid} seq {seq} ack {ack}: {msg.hex()}")
            self.upstreamHandler(self, self.sid, msg)

    def sendWithFragmentation(self, size, pdu):
        remaining = pdu
        while len(remaining) > 0:
            fragment = remaining[0:size]
            self.send(fragment)
            #time.sleep(0.01)
            remaining = remaining[size:]

    def send(self, pdu):
        msg = bytearray()
        seq = (self.sent << 1) & 0x7e
        ack = self.received & 0x3f
        self.acknowledged = self.received
        msg.append(seq)
        msg.append(ack)
        msg.extend(pdu)
        self.sent += 1
        #print(f"----- seqack sending: {msg.hex()}")
        self.connection.send_l2cap_pdu(self.replyCid, msg)

    def ackTimeout(self):
        while True:
            time.sleep(0.05)
            if self.acknowledged >= self.received:
                continue

            msg = bytearray()
            seq = 0x01
            ack = self.received & 0x3f
            self.acknowledged = self.received
            msg.append(seq)
            msg.append(ack)
            #print(f"----- seqack sending special ack: {msg.hex()}, time {time.time()}")
            self.connection.send_l2cap_pdu(self.replyCid, msg)

class NRLPHandler:

    def __init__(self, oobkey):
        self.socket = socket(AF_INET, SOCK_DGRAM)
        self.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.socket.bind(('', 0x5757))
        self.oobkey = oobkey
        self.sentPrelude = False
        self.sentUrgentPrelude = False
        self.pairingCompleted = False
        self.prelude = bytearray.fromhex("5445524d494e5553010a00130400100000000000000000a290b642288f42b58dea")

        receiver = threading.Thread(target=self.receiveRemote)
        receiver.start()

    seqack = None
    seqack_urgent = None
    clientAddr = None
    buffer = bytearray()
    buffer_urgent = bytearray()

    def overrideOOBKey(self, newKey):
        self.oobkey = newKey
        self.handoff(0x33, self.oobkey, False)

    def sendBtPIN(self, pin):
        self.handoff(0x34, bytearray(str(pin), "utf-8"), False)

    def disconnect(self):
        self.buffer = bytearray()
        self.buffer_urgent = bytearray()
        self.handoff(0x36, bytearray(b"disconnect"), False)

    def receiveRemote(self):
        
        print("listening")
        while True:
            (msg, addr) = self.socket.recvfrom(10000)
            #print(f"UDP connection from {addr} msg {msg.hex()}")
            if msg == b"nrlp-hello":
                self.pairingCompleted = False
                self.clientAddr = addr
                print("got hello")
                self.handoff(0x33, self.oobkey, False)
                continue
            elif msg[0] == 0x34:
                print(f"Got new prelude: {msg[1:].hex()}")
                self.prelude = msg[1:]
                continue
            #print(f"UDP received {msg.hex()}")
            typ = msg[0]
            urgent = (msg[1] == 1)
            payload = msg[2:]
            self.send(typ, payload, urgent)

    def handoff(self, typ, msg, isUrgent):
        payload = bytearray(typ.to_bytes(1, byteorder='big'))
        payload.extend((1 if isUrgent else 0).to_bytes(1, byteorder='big'))
        payload.extend(msg)
        print(f"UDP sending msg {payload.hex()}")
        self.sock_send(payload)

    def sock_send(self, msg):
        self.socket.sendto(msg, self.clientAddr)

    def ready(self):
        self.handoff(0x32, b"nrlp-hello", False)

    def ready_paired(self):
        self.handoff(0x35, b"nrlp-hello", False)

    def receive(self, msg):
        print(f"nrlp receive {len(msg)} bytes, {len(self.buffer)} in buffer")
        self.buffer.extend(msg)
        #print(f"new buffer len {len(self.buffer)}")
        self.processBuffer(False)

    def receiveUrgent(self, msg):
        print(f"nrlp urgent receive {len(msg)} bytes, {len(self.buffer)} in buffer")
        self.buffer_urgent.extend(msg)
        #print(f"new urgent buffer len {len(self.buffer_urgent)}")
        self.processBuffer(True)

    def processBuffer(self, isUrgent):
        buf = self.buffer_urgent if isUrgent else self.buffer

        if len(buf) < 3:
            return

        #print(f"processing buffer of size {len(buf)}")

        typ = buf[0]
        length = int.from_bytes(buf[1:3], byteorder='big')
        
        print(f"got NRLP header for type {typ} length {length}, time {time.time()}")

        if not typ in [0x03, 0x04, 0x64, 0x65, 0x68, 0x69]:
            print("SUSPICIOUS NRLP HEADER - packet boundary corruption?")

        print(f">>> {buf.hex()}")

        if length+5 > len(buf): # length+5 because we also need header (3) and checksum (2) bytes that are not included in the length field
            print(f"waiting for {length-len(buf)} more bytes")
            return

        # ... we're ignoring the checksum here
        msg = buf[3:3+length]

        if isUrgent:
            self.buffer_urgent = buf[3+length+2:]
        else:
            self.buffer = buf[3+length+2:]

        self.handoff(typ, msg, isUrgent)
        self.processBuffer(isUrgent)

    def send(self, typ, payload, isUrgent):
        msg = bytearray()
        msg.append(typ)
        msg.extend(len(payload).to_bytes(2, byteorder="big"))
        msg.extend(payload)

        checksum = None
        if typ < 0x64:
            checksum = self.checksum_ip(msg)
        else:
            checksum = self.checksum_custom(len(payload), typ)
        msg.extend(checksum)
       
        print(f"----- nrlp sending {typ}: {msg.hex()}")
        if isUrgent and self.seqack_urgent != None:
            self.seqack_urgent.sendWithFragmentation(260, msg) # original max pdu: 260
        else:
            self.seqack.sendWithFragmentation(260, msg) # original max pdu: 260

    def checksum_ip(self, pdu):
        csum = 0
        data = bytearray()

        data.extend(pdu)
        if len(data) % 2 == 1:
            data.append(0x00)

        for i in range(int(len(data)/2)):
            word = int.from_bytes(data[i*2:i*2+2], byteorder='big')
            csum += word
        csum += csum >> 16
        csum = csum & 0xFFFF ^ 0xFFFF
        return csum.to_bytes(2, byteorder="big")

    def checksum_custom(self, length, typ):
        csum_high = (length >> 8) ^ (typ >> 4)
        csum_low = ((length & 0xFF) ^ (typ << 4)) & 0xFF
        csum = bytearray()
        csum.append(csum_high)
        csum.append(csum_low)
        return csum

class NearbyStubResponder:
    def __init__(self, connection, replyCid, service):
        self.replyCid = replyCid
        self.connection = connection
        self.sid = service

    def receive(self, handle, pdu):
        print(f"----- nearby received for sid {self.sid}: {pdu.hex()}")
        self.send()
        

    def send(self):
        msg = bytearray.fromhex("01050101000000")
        print(f"----- nearby sending: {msg.hex()}")
        self.connection.send_l2cap_pdu(self.replyCid, msg)

class BTTSHandler:
    def __init__(self):
        self.idk = True

    def send(self, seqack):
        pdu = bytearray.fromhex("021f02000000020c01010100c60000001e0012000c020201000807000004006400")
        seqack.send(pdu)
        print(f"----- BT.TS sending {pdu.hex()}")
    
    def receive(self, seqack, sid, pdu):
        print(f"----- BT.TS received {pdu.hex()}")