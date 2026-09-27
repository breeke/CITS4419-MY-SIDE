import hashlib
import hmac
import ipaddress
import os
import random
import struct

# AES comes from the 'cryptography' package (pip install cryptography).
# HMAC and SHA-256 come from Python's standard library (hmac, hashlib)
try:
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    raise SystemExit("This simulator needs the 'cryptography' package: pip install cryptography")

DATA = 1
ACK = 2
CONTROL = 3

FRAME_TYPE = {
    1: "DATA",
    2: "ACK",
    3: "CONTROL"
}

BROADCAST_MAC = "FF:FF:FF:FF"

# ---------------------------------------------------------------------------
# IPv6 constants (Part B)
# ---------------------------------------------------------------------------
# Next Header values: tell the receiver which protocol is inside the IPv6 payload
NEXT_HEADER_UDP = 17        # payload is a UDP datagram (Part C)
NEXT_HEADER_ESP = 50        # payload is an IPsec ESP packet (Part D)
NEXT_HEADER_ICMPV6 = 58     # payload is an ICMPv6 message (carries RPL)
NEXT_HEADER_NONE = 59       # nothing follows the IPv6 header

# Simplified IPv6 header, packed with struct:
#   !    network byte order (big-endian), no padding
#   16s  Source IPv6 Address      (16 bytes)
#   16s  Destination IPv6 Address (16 bytes)
#   B    Next Header              (1 byte, unsigned)
#   H    Payload Length           (2 bytes, unsigned)
IPV6_HEADER_FORMAT = "!16s16sBH"
IPV6_HEADER_LEN = struct.calcsize(IPV6_HEADER_FORMAT)   # 35 bytes

# DIOs are sent to the link-local "all RPL nodes" multicast address.
# A multicast IPv6 destination maps to the broadcast MAC address.
ALL_RPL_NODES = "ff02::1a"

# Every IoT node's address is inside this prefix. The root uses it to decide
# whether a destination is inside the wireless network or out on the Internet
RPL_NETWORK = ipaddress.IPv6Network("fd00::/64")

# ---------------------------------------------------------------------------
# RPL constants (Part B)
# ---------------------------------------------------------------------------
ICMPV6_TYPE_RPL = 155       # ICMPv6 Type for RPL control messages
RPL_CODE_DIO = 1            # ICMPv6 Code for a DIO

# Simplified ICMPv6 RPL control message:
#   B  Type (1 byte), B  Code (1 byte), H  Rank (2 bytes)
RPL_FORMAT = "!BBH"
RPL_LEN = struct.calcsize(RPL_FORMAT)   # 4 bytes

INFINITE_RANK = float("inf")    # rank of a node that has not joined the DODAG yet
RANK_INCREASE = 1               # each wireless hop increases the rank by 1

# ---------------------------------------------------------------------------
# UDP constants (Part C)
# ---------------------------------------------------------------------------
# Simplified UDP header: Source Port, Destination Port, Length, Checksum
# (4 x 2-byte unsigned fields = 8 bytes)
UDP_HEADER_FORMAT = "!HHHH"
UDP_HEADER_LEN = struct.calcsize(UDP_HEADER_FORMAT)     # 8 bytes

COAP_SERVER_PORT = 5683     # well-known CoAP port the server listens on
COAP_CLIENT_PORT = 50000    # port the IoT node uses as a CoAP client

# ---------------------------------------------------------------------------
# CoAP constants (Part C)
# ---------------------------------------------------------------------------
COAP_VERSION = 1

# Message types (2 bits)
COAP_CON = 0    # Confirmable: must be acknowledged
COAP_NON = 1    # Non-confirmable
COAP_ACK = 2    # Acknowledgement
COAP_RST = 3    # Reset
COAP_TYPE_NAME = {0: "CON", 1: "NON", 2: "ACK", 3: "RST"}

# Codes are 8 bits written as c.dd: 3-bit class, 5-bit detail.
# Class 0 = request method, class 2 = success, class 4 = client error
COAP_POST = 0x02            # 0.02 POST
COAP_CHANGED = 0x44         # 2.04 Changed  (2 << 5 | 4)
COAP_NOT_FOUND = 0x84       # 4.04 Not Found (4 << 5 | 4)
COAP_CODE_NAME = {
    0x01: "GET", 0x02: "POST", 0x03: "PUT", 0x04: "DELETE",
    0x44: "2.04 Changed", 0x45: "2.05 Content", 0x84: "4.04 Not Found",
}

# Option numbers
COAP_OPTION_URI_PATH = 11
COAP_OPTION_CONTENT_FORMAT = 12
COAP_OPTION_NAME = {11: "Uri-Path", 12: "Content-Format"}

COAP_PAYLOAD_MARKER = 0xFF  # separates options from the payload

# Addresses of the CoAP server connected to A's wired interface
SERVER_MAC = "00:00:01:02"
SERVER_IPV6 = "2001:db8::1"

# ---------------------------------------------------------------------------
# Security constants (Part D)
# ---------------------------------------------------------------------------
# No key exchange is simulated: every node and the server are preconfigured
# with the same keys, as if IKE (IPsec) and the DTLS handshake already ran.
# AES-128 needs a 16-byte key; HMAC keys can be any length
IPSEC_ENC_KEY = b"IPSEC-ENC-KEY-01"     # 16 bytes
IPSEC_HMAC_KEY = b"IPSEC-HMAC-KEY1"     # 15 bytes
DTLS_ENC_KEY = b"0123456789ABCDEF"      # 16 bytes
DTLS_HMAC_KEY = b"ABCDEF0123456789"     # 16 bytes

# IPsec ESP (Transport Mode):
#   SPI (4) | Sequence Number (4) | IV (16) | Encrypted Payload | HMAC (32)
# The encrypted payload is the UDP datagram followed by the ESP Next Header
# byte (the ESP trailer), so the Next Header is also hidden from eavesdroppers
IPSEC_SPI = 0x00000001
ESP_HEADER_FORMAT = "!II"       # SPI, Sequence Number
ESP_HEADER_LEN = struct.calcsize(ESP_HEADER_FORMAT)     # 8 bytes
IV_LEN = 16                     # AES block size
HMAC_LEN = 32                   # full HMAC-SHA-256 output

# DTLS record (simplified, DTLS 1.2 field layout):
#   Type (1) | Version (2) | Epoch (2) | Sequence Number (6) | Length (2) | Protected Data
# Protected Data = IV (16) | AES-128-CBC ciphertext of the CoAP message | HMAC (32)
DTLS_HEADER_FORMAT = "!BHH6sH"
DTLS_HEADER_LEN = struct.calcsize(DTLS_HEADER_FORMAT)   # 13 bytes
DTLS_TYPE_APPLICATION_DATA = 23     # record carries application data (CoAP)
DTLS_VERSION_1_2 = 0xFEFD           # DTLS 1.2 on the wire
DTLS_EPOCH = 1                      # epoch 0 = handshake; 1 = after the keys are in use

# CoAP over DTLS uses its own well-known port ("coaps"), so the server can
# tell secured traffic (5684) apart from plain CoAP (5683)
COAPS_SERVER_PORT = 5684


def format_rank(rank):
    return "infinity" if rank == INFINITE_RANK else str(rank)


def internet_checksum(data):
    """
    16-bit one's complement checksum used by UDP.
    The data is added up as 16-bit words, any carry out of the top bit is
    wrapped back into the bottom, and the result is inverted.
    """
    if len(data) % 2:
        data += b"\x00"     # pad to a whole number of 16-bit words
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def udp_checksum(source_ipv6, destination_ipv6, udp_datagram):
    """
    The UDP checksum over IPv6 also covers a 'pseudo-header' taken from the
    IPv6 layer (addresses, length, Next Header). This lets the receiver detect
    a datagram that was delivered to the wrong address, not just corrupted.
    """
    pseudo_header = (
        ipaddress.IPv6Address(source_ipv6).packed
        + ipaddress.IPv6Address(destination_ipv6).packed
        + struct.pack("!I3xB", len(udp_datagram), NEXT_HEADER_UDP)
    )
    return internet_checksum(pseudo_header + udp_datagram)


def aes_cbc_encrypt(key, plaintext):
    """
    AES-128-CBC encryption. AES works on 16-byte blocks, so the plaintext is
    padded (PKCS7) to a multiple of 16. A fresh random IV makes the same
    plaintext encrypt to a different ciphertext every time.
    Returns (iv, ciphertext).
    """
    iv = os.urandom(IV_LEN)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv, encryptor.update(padded) + encryptor.finalize()


def aes_cbc_decrypt(key, iv, ciphertext):
    """Reverse of aes_cbc_encrypt: decrypt, then remove the PKCS7 padding."""
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def hmac_sha256(key, data):
    """32-byte HMAC-SHA-256 tag: only someone with the key can produce it."""
    return hmac.new(key, data, hashlib.sha256).digest()


def encode_option_nibble(value):
    """
    CoAP stores option delta and length in 4-bit fields. Values 0-12 fit
    directly; 13 means 'one extra byte follows', 14 'two extra bytes follow'.
    """
    if value < 13:
        return value, b""
    if value < 269:
        return 13, bytes([value - 13])
    return 14, struct.pack("!H", value - 269)


def decode_option_nibble(nibble, message, index):
    if nibble < 13:
        return nibble, index
    if nibble == 13:
        return message[index] + 13, index + 1
    return struct.unpack("!H", message[index:index + 2])[0] + 269, index + 2


def build_coap_message(msg_type, code, message_id, token, options, payload):
    """
    CoAP message layout:
      Byte 0    : Version (2 bits) | Type (2 bits) | Token Length (4 bits)
      Byte 1    : Code (8 bits)
      Bytes 2-3 : Message ID (16 bits)
      Token     : 0-8 bytes
      Options   : each = [delta nibble | length nibble] + value
      0xFF + Payload (only if there is a payload)
    """
    first_byte = (COAP_VERSION << 6) | (msg_type << 4) | len(token)
    message = struct.pack("!BBH", first_byte, code, message_id) + token

    # Options must be in increasing option-number order. Each option stores
    # the difference (delta) from the previous option number, not the number
    previous_number = 0
    for number, value in sorted(options):
        delta_nibble, delta_ext = encode_option_nibble(number - previous_number)
        length_nibble, length_ext = encode_option_nibble(len(value))
        message += bytes([(delta_nibble << 4) | length_nibble]) + delta_ext + length_ext + value
        previous_number = number

    if payload:
        message += bytes([COAP_PAYLOAD_MARKER]) + payload
    return message


def parse_coap_message(message):
    first_byte, code, message_id = struct.unpack("!BBH", message[:4])
    version = first_byte >> 6
    msg_type = (first_byte >> 4) & 0x03
    token_length = first_byte & 0x0F
    token = message[4:4 + token_length]

    index = 4 + token_length
    options = []
    payload = b""
    option_number = 0
    while index < len(message):
        if message[index] == COAP_PAYLOAD_MARKER:
            payload = message[index + 1:]
            break
        option_byte = message[index]
        index += 1
        delta, index = decode_option_nibble(option_byte >> 4, message, index)
        length, index = decode_option_nibble(option_byte & 0x0F, message, index)
        option_number += delta
        options.append((option_number, message[index:index + length]))
        index += length

    return {
        "version": version, "type": msg_type, "code": code,
        "message_id": message_id, "token": token,
        "options": options, "payload": payload,
    }


def format_coap_code(code):
    return COAP_CODE_NAME.get(code, f"{code >> 5}.{code & 0x1F:02d}")


def format_coap_options(options):
    parts = []
    for number, value in options:
        name = COAP_OPTION_NAME.get(number, f"Option {number}")
        if number == COAP_OPTION_URI_PATH:
            parts.append(f"{name}=/{value.decode()}")
        else:
            parts.append(f"{name}={int.from_bytes(value, 'big')}")
    return ", ".join(parts) if parts else "none"


class Node:
    def __init__(self, name, mac_address, ipv6_address):
        self.name = name
        self.label = f"Node {name}"     # prefix used in every log line
        self.mac_address = mac_address
        self.ipv6_address = ipv6_address
        self.neighbors = []
        self.mac_sequence_number = 0

        # RPL state. A is made root in create_network()
        self.rank = INFINITE_RANK
        self.preferred_parent = None    # Node object of the parent, None = unknown
        self.dio_pending = False        # True when this node must (re)advertise a DIO

        # Routing state (Part C)
        self.wired_neighbor = None      # only A (to the server) and the server (to A)
        # Downward routes learned from traffic passing up through this node:
        #   {IPv6 address of a node below me: the child it came from}
        self.downward_routes = {}

        # UDP / CoAP state (Part C)
        self.udp_listening_ports = {COAP_CLIENT_PORT}
        # RFC 7252 recommends starting Message IDs at a random value, so a
        # rebooted node does not reuse IDs the server has just seen
        self.coap_message_id = random.randint(0, 0xFFFF)
        # Outstanding CON requests waiting for their ACK: {Message ID: Token}
        self.pending_requests = {}

        # Security state (Part D), one entry per peer we talk to securely.
        # IPsec SA: SPI, our outgoing ESP sequence number, and the sequence
        # numbers already accepted from that peer (replay protection)
        self.ipsec_sas = {}
        # DTLS session: epoch, our outgoing record sequence number, and the
        # record sequence numbers already accepted from that peer
        self.dtls_sessions = {}

        # Copy of the last packet sent over the wired link, used to stage the
        # replay and tampering tests in Part D (an attacker on that link)
        self.last_wired_packet = None

    def get_ipsec_sa(self, peer_ipv6):
        # The SA is assumed to be already established (no IKE), so it is
        # created with its initial values the first time it is needed
        return self.ipsec_sas.setdefault(
            peer_ipv6, {"spi": IPSEC_SPI, "seq_out": 0, "accepted": set()}
        )

    def get_dtls_session(self, peer_ipv6):
        # Handshake assumed complete: epoch 1, record sequence numbers from 0
        return self.dtls_sessions.setdefault(
            peer_ipv6, {"epoch": DTLS_EPOCH, "seq_out": 0, "accepted": set()}
        )

    def setup(self):
        print(f"[{self.label}]")
        print(f"MAC: {self.mac_address}, IPv6: {self.ipv6_address} \n")

    def add_neighbour(self, neighbor):
        self.neighbors.append(neighbor)

    def find_neighbor_by_ipv6(self, ipv6_address):
        for neighbor in self.neighbors:
            if neighbor.ipv6_address == ipv6_address:
                return neighbor
        return None

    def find_neighbor_by_mac(self, mac_address):
        for neighbor in self.neighbors:
            if neighbor.mac_address == mac_address:
                return neighbor
        return None


    """
    MAC layer
    - Source MAC Address (4 bytes)
    - Destination MAC Address (4 bytes)
    - Sequence Number (1 byte)
    - Frame Type (1 byte) (DATA = 1, ACK = 2, CONTROL = 3)
    - Payload Length (2 bytes)
    - Payload (variable length)
    """
    def create_mac_frame(self, payload, destination_mac, frame_type):
        frame = {
            "source_mac": self.mac_address,
            "destination_mac": destination_mac,
            "sequence_number": self.mac_sequence_number,
            "frame_type": frame_type,
            "payload_length": len(payload),
            "payload": payload
        }

        return frame

    def send_mac(self, payload, destination_mac, frame_type):
        frame = self.create_mac_frame(
            payload,
            destination_mac,
            frame_type
        )

        # Increment sequence number after creating the frame.
        # The field is 1 byte, so it wraps from 255 back to 0
        self.mac_sequence_number = (self.mac_sequence_number + 1) % 256

        # Broadcast frame
        if destination_mac == BROADCAST_MAC:
            print(
                f"[{self.label}][MAC] Broadcasting {FRAME_TYPE[frame_type]} frame: "
                f"Destination MAC={destination_mac}, "
                f"Sequence={frame['sequence_number']}, "
                f"Payload Length={frame['payload_length']}"
            )
            for neighbor in self.neighbors:
                neighbor.receive_mac(frame)

        # Unicast frame
        else:
            print(
                f"[{self.label}][MAC] Sending {FRAME_TYPE[frame_type]} frame: "
                f"Source MAC={self.mac_address}, "
                f"Destination MAC={destination_mac}, "
                f"Sequence={frame['sequence_number']}, "
                f"Payload Length={frame['payload_length']}"
            )
            for neighbor in self.neighbors:
                if neighbor.mac_address == destination_mac:
                    neighbor.receive_mac(frame)
                    return

            print(
                f"[{self.label}][MAC] "
                f"Destination {destination_mac} is not a one-hop neighbor"
            )

    def receive_mac(self, frame):
        print(
            f"[{self.label}][MAC] Received {FRAME_TYPE[frame['frame_type']]} frame "
            f"from MAC={frame['source_mac']}, "
            f"Sequence={frame['sequence_number']}, "
            f"Payload Length={frame['payload_length']}"
        )

        # Unicast DATA frames require an ACK
        if frame["frame_type"] == DATA:
            print(
                f"[{self.label}][MAC] "
                f"DATA frame received, sending ACK"
            )

            self.send_mac_ack(
                frame["source_mac"],
                frame["sequence_number"]
            )

        elif frame["frame_type"] == ACK:
            print(
                f"[{self.label}][MAC] "
                f"ACK received for Sequence={frame['sequence_number']}"
            )
            # An ACK has no payload, so there is nothing to pass up
            return

        # DATA and CONTROL frames carry an IPv6 packet: decapsulate it.
        # The previous hop is passed up so IPv6 can learn downward routes
        print(f"[{self.label}][MAC] Extracting IPv6 packet from MAC payload")
        previous_hop = self.find_neighbor_by_mac(frame["source_mac"])
        self.receive_ipv6(frame["payload"], previous_hop)

    def send_mac_ack(self, destination_mac, sequence_number):
        frame = {
            "source_mac": self.mac_address,
            "destination_mac": destination_mac,
            "sequence_number": sequence_number,
            "frame_type": ACK,
            "payload_length": 0,
            "payload": b""
        }

        print(
            f"[{self.label}][MAC] Sending ACK: "
            f"Destination MAC={destination_mac}, "
            f"Sequence={sequence_number}"
        )

        for neighbor in self.neighbors:
            if neighbor.mac_address == destination_mac:
                neighbor.receive_mac(frame)
                return


    """
    Wired interface (Part C)
    Point-to-point link between root A and the CoAP server. It is not
    IEEE 802.15.4, so it has no sequence numbers or MAC ACKs: the frame just
    carries the source/destination MAC and the IPv6 packet
    """
    def send_wired(self, packet):
        peer = self.wired_neighbor
        frame = {
            "source_mac": self.mac_address,
            "destination_mac": peer.mac_address,
            "payload": packet,
        }
        print(
            f"[{self.label}][Wired] Sending frame over wired interface: "
            f"Source MAC={self.mac_address}, Destination MAC={peer.mac_address}, "
            f"Payload Length={len(packet)}"
        )
        self.last_wired_packet = packet
        peer.receive_wired(frame)

    def receive_wired(self, frame):
        print(
            f"[{self.label}][Wired] Received frame from MAC={frame['source_mac']}, "
            f"Payload Length={len(frame['payload'])}"
        )
        print(f"[{self.label}][Wired] Extracting IPv6 packet from wired frame")
        self.receive_ipv6(frame["payload"], self.wired_neighbor)


    """
    IPv6 layer
    - Source IPv6 Address (16 bytes)
    - Destination IPv6 Address (16 bytes)
    - Next Header (1 byte) (UDP = 17, ICMPv6 = 58, No Next Header = 59)
    - Payload Length (2 bytes)
    - Payload (variable length)
    """
    def send_ipv6(self, payload, destination_ipv6, next_header):
        # Build the 35-byte header. ipaddress(...).packed turns the text
        # address "fd00::1" into its full 16-byte binary form
        header = struct.pack(
            IPV6_HEADER_FORMAT,
            ipaddress.IPv6Address(self.ipv6_address).packed,
            ipaddress.IPv6Address(destination_ipv6).packed,
            next_header,
            len(payload)
        )
        packet = header + payload

        print(
            f"[{self.label}][IPv6] Encapsulating payload: "
            f"Source={self.ipv6_address}, Destination={destination_ipv6}, "
            f"Next Header={next_header}, Payload Length={len(payload)}"
        )

        # Choose the MAC destination for this packet
        if ipaddress.IPv6Address(destination_ipv6).is_multicast:
            # Multicast (e.g. DIO to ff02::1a) -> every one-hop neighbor
            self.send_mac(packet, BROADCAST_MAC, CONTROL)
        else:
            self.route_ipv6(packet, destination_ipv6)

    def route_ipv6(self, packet, destination_ipv6):
        """
        Pick the next hop for a unicast packet. Only the MAC addresses change
        from hop to hop; the IPv6 source/destination inside `packet` never do.
          1. Destination is below me (learned route) -> send down to that child
          2. I have a preferred parent               -> send up towards the root
          3. I am the root and the destination is
             outside the RPL network                 -> send over the wired link
        """
        if destination_ipv6 in self.downward_routes:
            child = self.downward_routes[destination_ipv6]
            print(
                f"[{self.label}][IPv6] Route lookup: {destination_ipv6} is reachable "
                f"via child {child.name} (downward)"
            )
            self.send_mac(packet, child.mac_address, DATA)

        elif self.preferred_parent is not None:
            print(
                f"[{self.label}][IPv6] Route lookup: {destination_ipv6} -> "
                f"preferred parent {self.preferred_parent.name} (upward, default route)"
            )
            self.send_mac(packet, self.preferred_parent.mac_address, DATA)

        elif (self.wired_neighbor is not None
              and ipaddress.IPv6Address(destination_ipv6) not in RPL_NETWORK):
            print(
                f"[{self.label}][IPv6] Route lookup: {destination_ipv6} is outside "
                f"the RPL network, forwarding through wired interface"
            )
            self.send_wired(packet)

        else:
            print(f"[{self.label}][IPv6] No route to {destination_ipv6}, dropping packet")

    def receive_ipv6(self, packet, previous_hop=None):
        if len(packet) < IPV6_HEADER_LEN:
            print(
                f"[{self.label}][IPv6] Packet too short for an IPv6 "
                f"header ({len(packet)} bytes), dropping"
            )
            return

        # Split the packet into header and payload, then unpack the header
        source_raw, destination_raw, next_header, payload_length = struct.unpack(
            IPV6_HEADER_FORMAT, packet[:IPV6_HEADER_LEN]
        )
        payload = packet[IPV6_HEADER_LEN:IPV6_HEADER_LEN + payload_length]

        # Convert the 16-byte addresses back to compressed text form
        source_ipv6 = str(ipaddress.IPv6Address(source_raw))
        destination_ipv6 = str(ipaddress.IPv6Address(destination_raw))
        is_multicast = ipaddress.IPv6Address(destination_ipv6).is_multicast

        print(
            f"[{self.label}][IPv6] Parsing IPv6 packet: "
            f"Source={source_ipv6}, Destination={destination_ipv6}, "
            f"Next Header={next_header}, Payload Length={payload_length}"
        )

        # Learn a downward route: a unicast packet that arrived from a
        # neighbor other than my parent came up from below, so its source
        # can be reached back through that neighbor
        if (not is_multicast
                and previous_hop is not None
                and previous_hop is not self.preferred_parent
                and previous_hop is not self.wired_neighbor
                and self.downward_routes.get(source_ipv6) is not previous_hop):
            self.downward_routes[source_ipv6] = previous_hop
            print(
                f"[{self.label}][IPv6] Learned downward route: "
                f"{source_ipv6} via {previous_hop.name}"
            )

        # Not addressed to me: forward it without touching the IPv6 header
        if destination_ipv6 != self.ipv6_address and not is_multicast:
            print(
                f"[{self.label}][IPv6] Not the final destination, forwarding packet "
                f"(IPv6 Source={source_ipv6} and Destination={destination_ipv6} unchanged)"
            )
            if next_header == NEXT_HEADER_ESP:
                # Transport Mode leaves the IPv6 header readable so routers can
                # forward, but they cannot read or alter the protected payload
                print(
                    f"[{self.label}][IPv6] Payload is ESP-encrypted: forwarding "
                    f"without being able to read the UDP/DTLS/CoAP inside"
                )
            self.route_ipv6(packet, destination_ipv6)
            return

        # Demultiplex using Next Header
        if next_header == NEXT_HEADER_ICMPV6:
            print(f"[{self.label}][IPv6] Passing ICMPv6 payload to RPL")
            self.receive_rpl(payload, source_ipv6)
        elif next_header == NEXT_HEADER_UDP:
            print(f"[{self.label}][IPv6] Passing UDP datagram to UDP layer")
            self.receive_udp(payload, source_ipv6, destination_ipv6)
        elif next_header == NEXT_HEADER_ESP:
            print(f"[{self.label}][IPv6] Next Header=50, passing ESP packet to IPsec")
            self.receive_ipsec(payload, source_ipv6, destination_ipv6)
        elif next_header == NEXT_HEADER_NONE:
            print(f"[{self.label}][IPv6] No Next Header, nothing to deliver")
        else:
            print(
                f"[{self.label}][IPv6] Unknown Next Header={next_header}, dropping"
            )


    """
    RPL layer (ICMPv6 RPL control message)
    - Type (1 byte) (RPL = 155)
    - Code (1 byte) (DIO = 1)
    - Rank (2 bytes)
    """
    def send_rpl(self):
        # Only a node that has joined the DODAG has a rank to advertise
        if self.rank == INFINITE_RANK:
            print(f"[{self.label}][RPL] Rank is infinity, cannot send DIO")
            return

        print(f"[{self.label}][RPL] Creating DIO: Rank={self.rank}")
        dio = struct.pack(RPL_FORMAT, ICMPV6_TYPE_RPL, RPL_CODE_DIO, self.rank)

        self.send_ipv6(dio, ALL_RPL_NODES, NEXT_HEADER_ICMPV6)

    def receive_rpl(self, message, source_ipv6):
        if len(message) < RPL_LEN:
            print(f"[{self.label}][RPL] Message too short, dropping")
            return

        icmp_type, code, advertised_rank = struct.unpack(RPL_FORMAT, message[:RPL_LEN])

        if icmp_type != ICMPV6_TYPE_RPL or code != RPL_CODE_DIO:
            print(
                f"[{self.label}][RPL] Unsupported ICMPv6 message "
                f"Type={icmp_type}, Code={code}, ignoring"
            )
            return

        # The DIO carries only the sender's IPv6 address, so look up
        # which neighbor sent it
        sender = self.find_neighbor_by_ipv6(source_ipv6)
        if sender is None:
            print(f"[{self.label}][RPL] DIO from unknown node {source_ipv6}, ignoring")
            return

        print(
            f"[{self.label}][RPL] Received DIO from {sender.name}: "
            f"Advertised Rank={advertised_rank}"
        )

        # The rank this node would have if it chose the sender as its parent
        candidate_rank = advertised_rank + RANK_INCREASE
        print(f"[{self.label}][RPL] Candidate Rank={candidate_rank}")

        # Lower rank = closer to the root. Only switch to a better parent
        if candidate_rank < self.rank:
            print(
                f"[{self.label}][RPL] Updating Rank from "
                f"{format_rank(self.rank)} to {candidate_rank}"
            )
            self.rank = candidate_rank
            self.preferred_parent = sender
            print(f"[{self.label}][RPL] Setting Preferred Parent={sender.name}")

            # Rank changed, so this node must advertise its new rank.
            # It is queued rather than sent here so the DIOs spread
            # outward from the root one hop at a time (see build_rpl_topology)
            self.dio_pending = True
        else:
            print(
                f"[{self.label}][RPL] Candidate Rank {candidate_rank} is not better "
                f"than current Rank {format_rank(self.rank)}, ignoring DIO"
            )


    """
    UDP layer (Part C)
    - Source Port (2 bytes)
    - Destination Port (2 bytes)
    - Length (2 bytes): UDP header + UDP payload
    - Checksum (2 bytes)
    """
    def send_udp(self, payload, destination_ipv6, source_port, destination_port,
                 protect_with_esp=False):
        length = UDP_HEADER_LEN + len(payload)

        # Checksum is calculated with the checksum field set to 0, then
        # the real value is written into the header
        datagram_without_checksum = struct.pack(
            UDP_HEADER_FORMAT, source_port, destination_port, length, 0
        ) + payload
        checksum = udp_checksum(self.ipv6_address, destination_ipv6, datagram_without_checksum)

        datagram = struct.pack(
            UDP_HEADER_FORMAT, source_port, destination_port, length, checksum
        ) + payload

        print(
            f"[{self.label}][UDP] Encapsulating payload: Source Port={source_port}, "
            f"Destination Port={destination_port}, Length={length}, "
            f"Checksum=0x{checksum:04x}"
        )
        if protect_with_esp:
            # Part D: the whole UDP datagram (header + DTLS record) goes into ESP
            self.send_ipsec(datagram, destination_ipv6)
        else:
            self.send_ipv6(datagram, destination_ipv6, NEXT_HEADER_UDP)

    def receive_udp(self, datagram, source_ipv6, destination_ipv6):
        if len(datagram) < UDP_HEADER_LEN:
            print(f"[{self.label}][UDP] Datagram too short, dropping")
            return

        source_port, destination_port, length, checksum = struct.unpack(
            UDP_HEADER_FORMAT, datagram[:UDP_HEADER_LEN]
        )
        payload = datagram[UDP_HEADER_LEN:length]

        print(
            f"[{self.label}][UDP] Parsing UDP header: Source Port={source_port}, "
            f"Destination Port={destination_port}, Length={length}, "
            f"Checksum=0x{checksum:04x}"
        )

        # Recalculate the checksum the same way the sender did and compare
        datagram_without_checksum = datagram[:6] + b"\x00\x00" + datagram[8:length]
        expected = udp_checksum(source_ipv6, destination_ipv6, datagram_without_checksum)
        if expected != checksum:
            print(
                f"[{self.label}][UDP] Checksum mismatch (expected 0x{expected:04x}), "
                f"dropping datagram"
            )
            return
        print(f"[{self.label}][UDP] Checksum verified")

        # Demultiplex using the ports
        if destination_port not in self.udp_listening_ports:
            print(
                f"[{self.label}][UDP] No service listening on port "
                f"{destination_port}, dropping"
            )
        elif COAPS_SERVER_PORT in (source_port, destination_port):
            # Traffic to or from the coaps port carries a DTLS record
            print(
                f"[{self.label}][UDP] Port {COAPS_SERVER_PORT} is CoAP over DTLS, "
                f"passing payload to DTLS"
            )
            self.receive_dtls(payload, source_ipv6, source_port)
        else:
            print(
                f"[{self.label}][UDP] Port {destination_port} is the CoAP service, "
                f"passing payload to CoAP"
            )
            self.receive_coap(payload, source_ipv6, source_port)


    """
    IPsec ESP layer, Transport Mode (Part D)
    - SPI (4 bytes)
    - Sequence Number (4 bytes)
    - IV (16 bytes)
    - Encrypted Payload: AES-128-CBC of [UDP datagram | ESP Next Header (1 byte)]
    - HMAC-SHA-256 (32 bytes) over SPI | Sequence Number | IV | Encrypted Payload
    The IPv6 header stays in the clear so the packet can still be routed.
    """
    def send_ipsec(self, datagram, destination_ipv6):
        sa = self.get_ipsec_sa(destination_ipv6)
        sa["seq_out"] += 1          # starts at 1, +1 for every new ESP packet
        sequence = sa["seq_out"]

        print(
            f"[{self.label}][IPsec] Protecting UDP datagram with ESP Transport Mode: "
            f"SPI=0x{sa['spi']:08x}, Sequence Number={sequence}"
        )

        # The ESP Next Header (17 = UDP) is appended to the payload and
        # encrypted with it, so the receiver learns what is inside only
        # after decryption
        plaintext = datagram + bytes([NEXT_HEADER_UDP])
        print(
            f"[{self.label}][IPsec] Plaintext (UDP datagram + ESP Next Header=17), "
            f"{len(plaintext)} bytes: {plaintext.hex()}"
        )

        iv, ciphertext = aes_cbc_encrypt(IPSEC_ENC_KEY, plaintext)
        print(f"[{self.label}][IPsec] IV: {iv.hex()}")
        print(
            f"[{self.label}][IPsec] Ciphertext (AES-128-CBC), "
            f"{len(ciphertext)} bytes: {ciphertext.hex()}"
        )

        # Encrypt-then-MAC: the HMAC covers the header fields and the
        # ciphertext, so changing any of them is detected
        header = struct.pack(ESP_HEADER_FORMAT, sa["spi"], sequence)
        tag = hmac_sha256(IPSEC_HMAC_KEY, header + iv + ciphertext)
        print(f"[{self.label}][IPsec] HMAC-SHA-256 (SPI|Seq|IV|Ciphertext): {tag.hex()}")

        esp_packet = header + iv + ciphertext + tag
        print(
            f"[{self.label}][IPsec] ESP packet built: {ESP_HEADER_LEN} + {IV_LEN} + "
            f"{len(ciphertext)} + {HMAC_LEN} = {len(esp_packet)} bytes, "
            f"passing to IPv6 with Next Header=50"
        )
        self.send_ipv6(esp_packet, destination_ipv6, NEXT_HEADER_ESP)

    def receive_ipsec(self, esp_packet, source_ipv6, destination_ipv6):
        if len(esp_packet) < ESP_HEADER_LEN + IV_LEN + 16 + HMAC_LEN:
            print(f"[{self.label}][IPsec] ESP packet too short, dropping")
            return

        spi, sequence = struct.unpack(ESP_HEADER_FORMAT, esp_packet[:ESP_HEADER_LEN])
        iv = esp_packet[ESP_HEADER_LEN:ESP_HEADER_LEN + IV_LEN]
        ciphertext = esp_packet[ESP_HEADER_LEN + IV_LEN:-HMAC_LEN]
        received_tag = esp_packet[-HMAC_LEN:]

        print(
            f"[{self.label}][IPsec] Received ESP packet: SPI=0x{spi:08x}, "
            f"Sequence Number={sequence}, {len(esp_packet)} bytes"
        )

        # The SPI tells the receiver which SA (keys, sequence state) to use
        sa = self.get_ipsec_sa(source_ipv6)
        if spi != sa["spi"]:
            print(f"[{self.label}][IPsec] Unknown SPI 0x{spi:08x}, dropping")
            return

        print(f"[{self.label}][IPsec] Received ciphertext, {len(ciphertext)} bytes: {ciphertext.hex()}")

        # 1. Integrity: recompute the HMAC and compare in constant time.
        #    Checked before decrypting, so forged packets are never processed
        expected_tag = hmac_sha256(IPSEC_HMAC_KEY, esp_packet[:ESP_HEADER_LEN] + iv + ciphertext)
        print(f"[{self.label}][IPsec] Received HMAC: {received_tag.hex()}")
        print(f"[{self.label}][IPsec] Computed HMAC: {expected_tag.hex()}")
        if not hmac.compare_digest(received_tag, expected_tag):
            print(
                f"[{self.label}][IPsec] HMAC verification FAILED: packet was modified "
                f"or not sent by the SA peer, dropping"
            )
            return
        print(f"[{self.label}][IPsec] HMAC verified: integrity and authenticity OK")

        # 2. Replay protection: a sequence number may only be accepted once
        if sequence in sa["accepted"]:
            print(
                f"[{self.label}][IPsec] REPLAY DETECTED: Sequence Number={sequence} "
                f"was already accepted, dropping"
            )
            return
        sa["accepted"].add(sequence)
        print(
            f"[{self.label}][IPsec] Replay check passed: Sequence Number={sequence} is new "
            f"(accepted so far: {sorted(sa['accepted'])})"
        )

        # 3. Confidentiality: decrypt and read the ESP Next Header
        plaintext = aes_cbc_decrypt(IPSEC_ENC_KEY, iv, ciphertext)
        datagram, esp_next_header = plaintext[:-1], plaintext[-1]
        print(
            f"[{self.label}][IPsec] Decrypted plaintext, {len(plaintext)} bytes: "
            f"{plaintext.hex()}"
        )

        if esp_next_header != NEXT_HEADER_UDP:
            print(f"[{self.label}][IPsec] ESP Next Header={esp_next_header} not supported, dropping")
            return
        print(f"[{self.label}][IPsec] ESP Next Header=17, passing UDP datagram to UDP")
        self.receive_udp(datagram, source_ipv6, destination_ipv6)


    """
    DTLS record layer (Part D)
    - Type (1 byte) (23 = application data)
    - Version (2 bytes) (0xFEFD = DTLS 1.2)
    - Epoch (2 bytes)
    - Sequence Number (6 bytes)
    - Length (2 bytes): length of the protected data
    - Protected Data: IV (16) | AES-128-CBC ciphertext of the CoAP message | HMAC (32)
    """
    def send_dtls(self, message, destination_ipv6, source_port, destination_port):
        session = self.get_dtls_session(destination_ipv6)
        sequence = session["seq_out"]
        session["seq_out"] += 1     # DTLS record sequence numbers start at 0 in each epoch

        print(
            f"[{self.label}][DTLS] Protecting CoAP message: Type=23 (application data), "
            f"Version=0x{DTLS_VERSION_1_2:04x}, Epoch={session['epoch']}, "
            f"Sequence Number={sequence}"
        )
        print(f"[{self.label}][DTLS] Plaintext (CoAP message), {len(message)} bytes: {message.hex()}")

        iv, ciphertext = aes_cbc_encrypt(DTLS_ENC_KEY, message)
        print(f"[{self.label}][DTLS] IV: {iv.hex()}")
        print(
            f"[{self.label}][DTLS] Ciphertext (AES-128-CBC), "
            f"{len(ciphertext)} bytes: {ciphertext.hex()}"
        )

        # The HMAC covers type, version, epoch and sequence number as well as
        # the ciphertext, so a record cannot be replayed under a new number
        sequence_bytes = sequence.to_bytes(6, "big")
        mac_input = (
            struct.pack("!BHH", DTLS_TYPE_APPLICATION_DATA, DTLS_VERSION_1_2, session["epoch"])
            + sequence_bytes + iv + ciphertext
        )
        tag = hmac_sha256(DTLS_HMAC_KEY, mac_input)
        print(f"[{self.label}][DTLS] HMAC-SHA-256 (header fields|IV|Ciphertext): {tag.hex()}")

        protected = iv + ciphertext + tag
        record = struct.pack(
            DTLS_HEADER_FORMAT, DTLS_TYPE_APPLICATION_DATA, DTLS_VERSION_1_2,
            session["epoch"], sequence_bytes, len(protected)
        ) + protected
        print(
            f"[{self.label}][DTLS] DTLS record built: {DTLS_HEADER_LEN}-byte header + "
            f"{len(protected)} bytes protected data = {len(record)} bytes, passing to UDP"
        )

        # DTLS output is carried by UDP, and in Part D that UDP datagram is
        # then protected again by IPsec ESP
        self.send_udp(record, destination_ipv6, source_port, destination_port,
                      protect_with_esp=True)

    def receive_dtls(self, record, source_ipv6, source_port):
        if len(record) < DTLS_HEADER_LEN + IV_LEN + 16 + HMAC_LEN:
            print(f"[{self.label}][DTLS] Record too short, dropping")
            return

        record_type, version, epoch, sequence_bytes, length = struct.unpack(
            DTLS_HEADER_FORMAT, record[:DTLS_HEADER_LEN]
        )
        sequence = int.from_bytes(sequence_bytes, "big")
        protected = record[DTLS_HEADER_LEN:DTLS_HEADER_LEN + length]
        iv = protected[:IV_LEN]
        ciphertext = protected[IV_LEN:-HMAC_LEN]
        received_tag = protected[-HMAC_LEN:]

        print(
            f"[{self.label}][DTLS] Parsing DTLS record: Type={record_type}, "
            f"Version=0x{version:04x}, Epoch={epoch}, Sequence Number={sequence}, "
            f"Length={length}"
        )

        session = self.get_dtls_session(source_ipv6)
        if record_type != DTLS_TYPE_APPLICATION_DATA or epoch != session["epoch"]:
            print(f"[{self.label}][DTLS] Unexpected record type or epoch, dropping")
            return

        print(f"[{self.label}][DTLS] Received ciphertext, {len(ciphertext)} bytes: {ciphertext.hex()}")

        # 1. Integrity
        mac_input = record[:DTLS_HEADER_LEN - 2] + iv + ciphertext     # header without Length
        expected_tag = hmac_sha256(DTLS_HMAC_KEY, mac_input)
        print(f"[{self.label}][DTLS] Received HMAC: {received_tag.hex()}")
        print(f"[{self.label}][DTLS] Computed HMAC: {expected_tag.hex()}")
        if not hmac.compare_digest(received_tag, expected_tag):
            print(f"[{self.label}][DTLS] HMAC verification FAILED, dropping record")
            return
        print(f"[{self.label}][DTLS] HMAC verified: integrity and authenticity OK")

        # 2. Replay protection (per epoch)
        if sequence in session["accepted"]:
            print(
                f"[{self.label}][DTLS] REPLAY DETECTED: Sequence Number={sequence} "
                f"was already accepted, dropping"
            )
            return
        session["accepted"].add(sequence)
        print(f"[{self.label}][DTLS] Replay check passed: Sequence Number={sequence} is new")

        # 3. Decrypt and hand the CoAP message up
        message = aes_cbc_decrypt(DTLS_ENC_KEY, iv, ciphertext)
        print(f"[{self.label}][DTLS] Decrypted plaintext (CoAP message), {len(message)} bytes: {message.hex()}")
        print(f"[{self.label}][DTLS] Passing CoAP message to CoAP")
        self.receive_coap(message, source_ipv6, source_port, secure=True)


    """
    CoAP layer (Part C)
    - Version (2 bits), Type (2 bits), Token Length (4 bits)
    - Code (8 bits)
    - Message ID (16 bits)
    - Token (0-8 bytes)
    - Options (variable)
    - 0xFF + Payload (variable)
    """
    def send_coap(self, destination_ipv6, source_port, destination_port,
                  msg_type, code, message_id, token, options, payload, secure=False):
        message = build_coap_message(msg_type, code, message_id, token, options, payload)

        print(
            f"[{self.label}][CoAP] Creating {COAP_TYPE_NAME[msg_type]} "
            f"{format_coap_code(code)} message: Message ID=0x{message_id:04x}, "
            f"Token=0x{token.hex()}, Options: {format_coap_options(options)}, "
            f"Payload='{payload.decode()}'"
        )
        print(f"[{self.label}][CoAP] Message bytes ({len(message)}): {message.hex(' ')}")

        if secure:
            # Part D: CoAP -> DTLS -> UDP -> IPsec ESP -> IPv6 -> MAC
            self.send_dtls(message, destination_ipv6, source_port, destination_port)
        else:
            # Part C: CoAP -> UDP -> IPv6 -> MAC
            self.send_udp(message, destination_ipv6, source_port, destination_port)

    def receive_coap(self, message, source_ipv6, source_port, secure=False):
        if len(message) < 4:
            print(f"[{self.label}][CoAP] Message too short, dropping")
            return

        coap = parse_coap_message(message)
        print(f"[{self.label}][CoAP] Message bytes ({len(message)}): {message.hex(' ')}")
        print(
            f"[{self.label}][CoAP] Parsing CoAP message: Version={coap['version']}, "
            f"Type={COAP_TYPE_NAME[coap['type']]}, Code={format_coap_code(coap['code'])}, "
            f"Message ID=0x{coap['message_id']:04x}, Token=0x{coap['token'].hex()}, "
            f"Options: {format_coap_options(coap['options'])}, "
            f"Payload='{coap['payload'].decode()}'"
        )

        # Request codes are class 0 (code < 32); responses are class 2-5
        if coap["code"] != 0 and coap["code"] < 32:
            self.handle_coap_request(coap, source_ipv6, source_port, secure)
        elif coap["type"] == COAP_ACK:
            self.handle_coap_response(coap)
        else:
            print(f"[{self.label}][CoAP] Unexpected message, ignoring")

    def handle_coap_request(self, coap, source_ipv6, source_port, secure=False):
        # IoT nodes only act as CoAP clients; the Server class overrides this
        print(f"[{self.label}][CoAP] This node does not host CoAP resources, ignoring request")

    def handle_coap_response(self, coap):
        # Message ID matches the ACK to our CON (stops retransmission);
        # Token matches the response to our request
        message_id = coap["message_id"]
        if message_id not in self.pending_requests:
            print(
                f"[{self.label}][CoAP] ACK Message ID=0x{message_id:04x} does not "
                f"match any outstanding request, ignoring"
            )
            return

        expected_token = self.pending_requests.pop(message_id)
        print(
            f"[{self.label}][CoAP] ACK matches outstanding CON "
            f"Message ID=0x{message_id:04x}, stopping retransmission"
        )
        if coap["token"] != expected_token:
            print(f"[{self.label}][CoAP] Token mismatch, response does not belong to this request")
            return

        print(
            f"[{self.label}][CoAP] Token=0x{coap['token'].hex()} matches request. "
            f"Piggybacked response: {format_coap_code(coap['code'])}, "
            f"Payload='{coap['payload'].decode()}'"
        )

    def next_coap_message_id(self):
        message_id = self.coap_message_id
        self.coap_message_id = (self.coap_message_id + 1) % 0x10000
        return message_id

    def send_sensor_data(self, server_ipv6, secure=False):
        """
        Application: read a temperature and POST it to the CoAP server.
        secure=False -> Part C (plain CoAP), secure=True -> Part D (DTLS + IPsec)
        """
        temperature = round(random.uniform(18.0, 30.0), 1)
        print(f"[{self.label}][App] Generated sensor reading: Temperature={temperature}°C")

        # Message ID: 16-bit, detects duplicates and pairs the ACK with this CON.
        # Token: random bytes chosen by the client that pair the response with
        # this request (and make responses harder to spoof)
        message_id = self.next_coap_message_id()
        token = os.urandom(4)
        self.pending_requests[message_id] = token

        options = [
            (COAP_OPTION_URI_PATH, b"temperature"),     # resource /temperature
            (COAP_OPTION_CONTENT_FORMAT, b""),          # 0 = text/plain (0 is sent as empty value)
        ]
        # Part C uses plain CoAP on port 5683; Part D uses CoAP over DTLS
        # ("coaps") on port 5684
        server_port = COAPS_SERVER_PORT if secure else COAP_SERVER_PORT
        self.send_coap(
            server_ipv6, COAP_CLIENT_PORT, server_port,
            COAP_CON, COAP_POST, message_id, token,
            options, str(temperature).encode(), secure=secure
        )


class Server(Node):
    """
    CoAP server connected to root A through A's wired interface.
    It reuses Node's IPv6, UDP and CoAP functions; it has no wireless
    neighbors and does not take part in RPL.
    """
    def __init__(self, mac_address, ipv6_address):
        super().__init__("Server", mac_address, ipv6_address)
        self.label = "Server"
        # 5683 = plain CoAP (Part C), 5684 = CoAP over DTLS (Part D)
        self.udp_listening_ports = {COAP_SERVER_PORT, COAPS_SERVER_PORT}
        self.resources = {"temperature": []}    # stored sensor readings

    def route_ipv6(self, packet, destination_ipv6):
        # Everything the server sends goes to the gateway, root A
        print(
            f"[{self.label}][IPv6] Route lookup: {destination_ipv6} is in the IoT "
            f"network, sending to gateway {self.wired_neighbor.name}"
        )
        self.send_wired(packet)

    def handle_coap_request(self, coap, source_ipv6, source_port, secure=False):
        uri_path = "/".join(
            value.decode() for number, value in coap["options"]
            if number == COAP_OPTION_URI_PATH
        )

        if coap["code"] == COAP_POST and uri_path in self.resources:
            value = coap["payload"].decode()
            self.resources[uri_path].append((source_ipv6, value))
            print(
                f"[{self.label}][CoAP] POST /{uri_path}: stored Temperature={value}°C "
                f"from {source_ipv6}"
            )
            response_code = COAP_CHANGED
            response_payload = f"Stored {value}C".encode()
        else:
            print(f"[{self.label}][CoAP] Resource /{uri_path} not found")
            response_code = COAP_NOT_FOUND
            response_payload = b"Not Found"

        if coap["type"] != COAP_CON:
            return  # a NON request gets no ACK

        # Piggybacked response: the response is carried inside the ACK itself.
        # The ACK reuses the request's Message ID and the response echoes its Token
        print(
            f"[{self.label}][CoAP] Sending piggybacked ACK response "
            f"(same Message ID=0x{coap['message_id']:04x}, same Token=0x{coap['token'].hex()})"
        )
        # A request that arrived over DTLS + ESP is answered the same way,
        # so the response is protected too
        server_port = COAPS_SERVER_PORT if secure else COAP_SERVER_PORT
        self.send_coap(
            source_ipv6, server_port, source_port,
            COAP_ACK, response_code, coap["message_id"], coap["token"],
            [], response_payload, secure=secure
        )


def create_network():
    # Create nodes using the addresses specified in Part A
    nodes = {
        "A": Node("A", "00:00:00:01", "fd00::1"),
        "B": Node("B", "00:00:00:02", "fd00::2"),
        "C": Node("C", "00:00:00:03", "fd00::3"),
        "D": Node("D", "00:00:00:04", "fd00::4"),
        "E": Node("E", "00:00:00:05", "fd00::5"),
    }

    # Add one-hop neighbours
    nodes["A"].add_neighbour(nodes["B"])
    nodes["A"].add_neighbour(nodes["C"])

    nodes["B"].add_neighbour(nodes["A"])
    nodes["B"].add_neighbour(nodes["D"])

    nodes["C"].add_neighbour(nodes["A"])
    nodes["C"].add_neighbour(nodes["E"])

    nodes["D"].add_neighbour(nodes["B"])

    nodes["E"].add_neighbour(nodes["C"])

    # A is the RPL root
    nodes["A"].rank = 0

    # CoAP server on the other end of A's wired interface
    server = Server(SERVER_MAC, SERVER_IPV6)
    nodes["A"].wired_neighbor = server
    server.wired_neighbor = nodes["A"]

    return nodes, server

def test_part_a(nodes):
    print("\nPART A TESTS\n")

    # Test 1:
    # Send a unicast DATA frame from A to B
    # Because B is a direct one-hop neighbor of A, the frame should be delivered
    # B should then return a MAC ACK using the same sequence number
    print("Test 1: Unicast DATA A to B")
    nodes["A"].send_mac(
        payload=b"Hello B",
        destination_mac=nodes["B"].mac_address,
        frame_type=DATA
    )

    print()

    # Test 2:
    # Send a unicast DATA frame from A to C
    # This checks that A's MAC sequence number increments
    print("Test 2: Unicast DATA A to C")
    nodes["A"].send_mac(
        payload=b"Hello C",
        destination_mac=nodes["C"].mac_address,
        frame_type=DATA
    )

    print()

    # Test 3:
    # Broadcast a CONTROL frame from A
    # A's one-hop neighbors are B and C, so both should receive the frame
    # Broadcast frames do not generate MAC ACKs
    print("Test 3: Broadcast CONTROL from A")
    nodes["A"].send_mac(
        payload=b"RPL control message",
        destination_mac=BROADCAST_MAC,
        frame_type=CONTROL
    )

    print()

    # Test 4:
    # Attempt to send a unicast from A to D
    # D is not a one-hop neighbor of A, so the MAC layer should not deliver the frame
    print("Test 4: Invalid one-hop transmission A to D")
    nodes["A"].send_mac(
        payload=b"Hello D",
        destination_mac=nodes["D"].mac_address,
        frame_type=DATA
    )

    print()

    # Test 5:
    # Send a DATA frame from D to B
    # This confirms that communication works for nodes other than A
    print("Test 5: Unicast DATA D -> B")
    nodes["D"].send_mac(
        payload=b"Hello from D",
        destination_mac=nodes["B"].mac_address,
        frame_type=DATA
    )

def build_rpl_topology(nodes):
    print("\nPART B: RPL TOPOLOGY CONSTRUCTION\n")

    # The root starts the process by advertising Rank = 0
    nodes["A"].dio_pending = True

    # Keep sending DIOs until no node has a new rank to advertise.
    # Each pass sends the DIOs queued in the previous pass, so the
    # topology grows one hop per round: A, then B and C, then D and E
    round_number = 1
    while any(node.dio_pending for node in nodes.values()):
        senders = [node for node in nodes.values() if node.dio_pending]
        print(f"--- DIO round {round_number}: "
              f"{', '.join(node.name for node in senders)} ---\n")

        for node in senders:
            node.dio_pending = False
            node.send_rpl()
            print()

        round_number += 1

    # Summary of the converged DODAG
    print("RPL topology converged:")
    for node in nodes.values():
        parent = node.preferred_parent.name if node.preferred_parent else "None (root)"
        print(f"  Node {node.name}: Rank={format_rank(node.rank)}, Preferred Parent={parent}")

def run_part_c(source, server):
    print(f"\nPART C: CoAP over UDP from Node {source.name} to Server\n")
    source.send_sensor_data(server.ipv6_address)
    print(f"\nServer has stored readings: {server.resources['temperature']}")

def run_part_d(source, server, gateway):
    print(f"\nPART D: CoAP secured with DTLS and IPsec ESP from Node {source.name} to Server")
    print("Keys are preconfigured, the IPsec SA (SPI=0x00000001) is established and")
    print("the DTLS handshake is complete. Encapsulation order at the sender:")
    print("  MAC -> IPv6 (Next Header=50) -> IPsec ESP -> UDP -> DTLS -> CoAP\n")

    source.send_sensor_data(server.ipv6_address, secure=True)
    print(f"\nServer has stored readings: {server.resources['temperature']}")

    run_security_tests(server, gateway)

def run_security_tests(server, gateway):
    """
    Act as an attacker on the wired link between A and the server, who
    captured the ESP-protected request that A just forwarded.
    """
    captured = gateway.last_wired_packet
    if captured is None:
        return
    frame_from_gateway = {"source_mac": gateway.mac_address}

    # Test 1: tampering. Flip one bit of the first ESP ciphertext byte.
    # Without the HMAC key the attacker cannot produce a matching HMAC
    print("\n--- Security test 1: attacker modifies one ciphertext byte ---\n")
    tampered = bytearray(captured)
    tampered[IPV6_HEADER_LEN + ESP_HEADER_LEN + IV_LEN] ^= 0x01
    server.receive_wired({**frame_from_gateway, "payload": bytes(tampered)})

    # Test 2: replay. Resend the captured packet unchanged. Its HMAC is
    # valid, but its ESP sequence number has already been accepted
    print("\n--- Security test 2: attacker replays the captured packet ---\n")
    server.receive_wired({**frame_from_gateway, "payload": captured})

    print(f"\nServer's stored readings are unchanged: {server.resources['temperature']}")

def run_user_menu(nodes, server):
    while True:
        try:
            part = input("\nSelect part to run (C or D, Q to quit): ").strip().upper()
            if part == "Q":
                return
            if part not in ("C", "D"):
                print("Please enter C, D or Q")
                continue

            source_name = input("Select source node (A, B, C, D or E): ").strip().upper()
            if source_name not in nodes:
                print("Please enter one of A, B, C, D or E")
                continue
        except EOFError:
            return

        if part == "C":
            run_part_c(nodes[source_name], server)
        else:
            run_part_d(nodes[source_name], server, nodes["A"])

def main():
    nodes, server = create_network()

    for node in nodes.values():
        node.setup()
    server.setup()

    # Uncomment to rerun the Part A MAC tests
    # test_part_a(nodes)

    build_rpl_topology(nodes)

    run_user_menu(nodes, server)


if __name__ == "__main__":
    main()
