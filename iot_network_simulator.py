DATA = 1
ACK = 2
CONTROL = 3

FRAME_TYPE = {
    1: "DATA",
    2: "ACK",
    3: "CONTROL"
}

BROADCAST_MAC = "FF:FF:FF:FF"

class Node:
    def __init__(self, name, mac_address, ipv6_address):
        self.name = name
        self.mac_address = mac_address
        self.ipv6_address = ipv6_address
        self.neighbors = []
        self.mac_sequence_number = 0

    def setup(self):
        print(f"[Node {self.name}]")
        print(f"MAC: {self.mac_address}, IPv6: {self.ipv6_address} \n")

    def add_neighbour(self, neighbor):
        self.neighbors.append(neighbor)


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

        print(
            f"[Node {self.name}] Sending frame to: "
            f"MAC: {destination_mac}, "
            f"Type: {FRAME_TYPE[frame_type]}, "
            f"Sequence: {frame['sequence_number']}"
        )

        # Increment sequence number after creating the frame
        self.mac_sequence_number += 1

        # Broadcast frame
        if destination_mac == BROADCAST_MAC:
            for neighbor in self.neighbors:
                neighbor.receive_mac(frame)

        # Unicast frame
        else:
            for neighbor in self.neighbors:
                if neighbor.mac_address == destination_mac:
                    neighbor.receive_mac(frame)
                    return

            print(
                f"[Node {self.name}] "
                f"Destination {destination_mac} is not a one-hop neighbor"
            )   

    def receive_mac(self, frame):
        print(
            f"[Node {self.name}] Received frame from: "
            f"MAC: {frame['source_mac']}: "
            f"Type: {FRAME_TYPE[frame['frame_type']]}, "
            f"Sequence: {frame['sequence_number']}"
        )

        print(
            f"[Node {self.name}] "
            f"Payload Length: {frame['payload_length']} bytes"
        )

        # Unicast DATA frames require an ACK
        if frame["frame_type"] == DATA:
            print(
                f"[Node {self.name}] "
                f"DATA frame received, sending ACK"
            )

            self.send_mac_ack(
                frame["source_mac"],
                frame["sequence_number"]
            )

        elif frame["frame_type"] == ACK:
            print(
                f"[Node {self.name}] "
                f"ACK received for Sequence: {frame['sequence_number']}"
            )

        elif frame["frame_type"] == CONTROL:
            print(
                f"[Node {self.name}] "
                f"CONTROL frame received"
            )
            
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
            f"[Node {self.name}] Sending ACK: "
            f"Destination MAC: {destination_mac}, "
            f"Sequence: {sequence_number}"
        )

        for neighbor in self.neighbors:
            if neighbor.mac_address == destination_mac:
                neighbor.receive_mac(frame)
                return


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
    
def main():
    nodes = create_network()

    for node in nodes.values():
        node.setup()
    
    test_part_a(nodes)


if __name__ == "__main__":
    main()