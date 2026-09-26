import ipaddress
import struct

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


def format_rank(rank):
    return "infinity" if rank == INFINITE_RANK else str(rank)


class Node:
    def __init__(self, name, mac_address, ipv6_address):
        self.name = name
        self.mac_address = mac_address
        self.ipv6_address = ipv6_address
        self.neighbors = []
        self.mac_sequence_number = 0

        # RPL state. A is made root in create_network()
        self.rank = INFINITE_RANK
        self.preferred_parent = None    # Node object of the parent, None = unknown
        self.dio_pending = False        # True when this node must (re)advertise a DIO

    def setup(self):
        print(f"[Node {self.name}]")
        print(f"MAC: {self.mac_address}, IPv6: {self.ipv6_address} \n")

    def add_neighbour(self, neighbor):
        self.neighbors.append(neighbor)

    def find_neighbor_by_ipv6(self, ipv6_address):
        for neighbor in self.neighbors:
            if neighbor.ipv6_address == ipv6_address:
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
                f"[Node {self.name}][MAC] Broadcasting {FRAME_TYPE[frame_type]} frame: "
                f"Destination MAC={destination_mac}, "
                f"Sequence={frame['sequence_number']}, "
                f"Payload Length={frame['payload_length']}"
            )
            for neighbor in self.neighbors:
                neighbor.receive_mac(frame)

        # Unicast frame
        else:
            print(
                f"[Node {self.name}][MAC] Sending {FRAME_TYPE[frame_type]} frame: "
                f"Destination MAC={destination_mac}, "
                f"Sequence={frame['sequence_number']}, "
                f"Payload Length={frame['payload_length']}"
            )
            for neighbor in self.neighbors:
                if neighbor.mac_address == destination_mac:
                    neighbor.receive_mac(frame)
                    return

            print(
                f"[Node {self.name}][MAC] "
                f"Destination {destination_mac} is not a one-hop neighbor"
            )

    def receive_mac(self, frame):
        print(
            f"[Node {self.name}][MAC] Received {FRAME_TYPE[frame['frame_type']]} frame "
            f"from MAC={frame['source_mac']}, "
            f"Sequence={frame['sequence_number']}, "
            f"Payload Length={frame['payload_length']}"
        )

        # Unicast DATA frames require an ACK
        if frame["frame_type"] == DATA:
            print(
                f"[Node {self.name}][MAC] "
                f"DATA frame received, sending ACK"
            )

            self.send_mac_ack(
                frame["source_mac"],
                frame["sequence_number"]
            )

        elif frame["frame_type"] == ACK:
            print(
                f"[Node {self.name}][MAC] "
                f"ACK received for Sequence={frame['sequence_number']}"
            )
            # An ACK has no payload, so there is nothing to pass up
            return

        # DATA and CONTROL frames carry an IPv6 packet: decapsulate it
        print(f"[Node {self.name}][MAC] Extracting IPv6 packet from MAC payload")
        self.receive_ipv6(frame["payload"])

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
            f"[Node {self.name}][MAC] Sending ACK: "
            f"Destination MAC={destination_mac}, "
            f"Sequence={sequence_number}"
        )

        for neighbor in self.neighbors:
            if neighbor.mac_address == destination_mac:
                neighbor.receive_mac(frame)
                return


    """
    IPv6 layer
    - Source IPv6 Address (16 bytes)
    - Destination IPv6 Address (16 bytes)
    - Next Header (1 byte) (ICMPv6 = 58, No Next Header = 59)
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
            f"[Node {self.name}][IPv6] Encapsulating payload: "
            f"Source={self.ipv6_address}, Destination={destination_ipv6}, "
            f"Next Header={next_header}, Payload Length={len(payload)}"
        )

        # Choose the MAC destination for this packet
        if ipaddress.IPv6Address(destination_ipv6).is_multicast:
            # Multicast (e.g. DIO to ff02::1a) -> every one-hop neighbor
            self.send_mac(packet, BROADCAST_MAC, CONTROL)
        else:
            # Unicast routing along the RPL tree is added in Part C
            print(
                f"[Node {self.name}][IPv6] No route to {destination_ipv6} "
                f"(unicast routing not implemented yet)"
            )

    def receive_ipv6(self, packet):
        if len(packet) < IPV6_HEADER_LEN:
            print(
                f"[Node {self.name}][IPv6] Packet too short for an IPv6 "
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

        print(
            f"[Node {self.name}][IPv6] Parsing IPv6 packet: "
            f"Source={source_ipv6}, Destination={destination_ipv6}, "
            f"Next Header={next_header}, Payload Length={payload_length}"
        )

        # Accept packets addressed to this node or to a multicast group
        is_for_me = (
            destination_ipv6 == self.ipv6_address
            or ipaddress.IPv6Address(destination_ipv6).is_multicast
        )
        if not is_for_me:
            # Forwarding towards another node is added in Part C
            print(f"[Node {self.name}][IPv6] Packet not for this node, dropping")
            return

        # Demultiplex using Next Header
        if next_header == NEXT_HEADER_ICMPV6:
            print(f"[Node {self.name}][IPv6] Passing ICMPv6 payload to RPL")
            self.receive_rpl(payload, source_ipv6)
        elif next_header == NEXT_HEADER_NONE:
            print(f"[Node {self.name}][IPv6] No Next Header, nothing to deliver")
        else:
            print(
                f"[Node {self.name}][IPv6] Unknown Next Header={next_header}, dropping"
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
            print(f"[Node {self.name}][RPL] Rank is infinity, cannot send DIO")
            return

        print(f"[Node {self.name}][RPL] Creating DIO: Rank={self.rank}")
        dio = struct.pack(RPL_FORMAT, ICMPV6_TYPE_RPL, RPL_CODE_DIO, self.rank)

        self.send_ipv6(dio, ALL_RPL_NODES, NEXT_HEADER_ICMPV6)

    def receive_rpl(self, message, source_ipv6):
        if len(message) < RPL_LEN:
            print(f"[Node {self.name}][RPL] Message too short, dropping")
            return

        icmp_type, code, advertised_rank = struct.unpack(RPL_FORMAT, message[:RPL_LEN])

        if icmp_type != ICMPV6_TYPE_RPL or code != RPL_CODE_DIO:
            print(
                f"[Node {self.name}][RPL] Unsupported ICMPv6 message "
                f"Type={icmp_type}, Code={code}, ignoring"
            )
            return

        # The DIO carries only the sender's IPv6 address, so look up
        # which neighbor sent it
        sender = self.find_neighbor_by_ipv6(source_ipv6)
        if sender is None:
            print(f"[Node {self.name}][RPL] DIO from unknown node {source_ipv6}, ignoring")
            return

        print(
            f"[Node {self.name}][RPL] Received DIO from {sender.name}: "
            f"Advertised Rank={advertised_rank}"
        )

        # The rank this node would have if it chose the sender as its parent
        candidate_rank = advertised_rank + RANK_INCREASE
        print(f"[Node {self.name}][RPL] Candidate Rank={candidate_rank}")

        # Lower rank = closer to the root. Only switch to a better parent
        if candidate_rank < self.rank:
            print(
                f"[Node {self.name}][RPL] Updating Rank from "
                f"{format_rank(self.rank)} to {candidate_rank}"
            )
            self.rank = candidate_rank
            self.preferred_parent = sender
            print(f"[Node {self.name}][RPL] Setting Preferred Parent={sender.name}")

            # Rank changed, so this node must advertise its new rank.
            # It is queued rather than sent here so the DIOs spread
            # outward from the root one hop at a time (see build_rpl_topology)
            self.dio_pending = True
        else:
            print(
                f"[Node {self.name}][RPL] Candidate Rank {candidate_rank} is not better "
                f"than current Rank {format_rank(self.rank)}, ignoring DIO"
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

    return nodes

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

def main():
    nodes = create_network()

    for node in nodes.values():
        node.setup()

    # Uncomment to rerun the Part A MAC tests
    # test_part_a(nodes)

    build_rpl_topology(nodes)


if __name__ == "__main__":
    main()
