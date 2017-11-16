
import tcp_packet
import utils
import wan_optimizer

class WanOptimizer(wan_optimizer.BaseWanOptimizer):
    """ WAN Optimizer that divides data into fixed-size blocks.
    This WAN optimizer should implement part 1 of project 4.
    """

    # Size of blocks to store, and send only the hash when the block has been
    # sent previously
    BLOCK_SIZE = 8000

    def __init__(self):
        wan_optimizer.BaseWanOptimizer.__init__(self)
        # Add any code that you like here (but do not add any constructor arguments).

        self.dest_packetSize = {}
        self.hash_packetList = {}
        self.dest_packetList = {}
        self.dest_block = {}


    def initializer(self, packet, flag):
        if flag or packet.dest not in self.dest_packetSize:
            self.dest_packetSize[packet.dest] = 0
        if flag or packet.dest not in self.dest_packetList:
            self.dest_packetList[packet.dest] = []
        if flag or packet.dest not in self.dest_block:
            self.dest_block[packet.dest] = ""


    def receive(self, packet):
        self.initializer(packet, False)
        if packet.is_raw_data:
            self.handle_raw_data(packet)
        else:
            self.send_code(packet, self.hash_packetList[packet.payload])
            self.initializer(packet, True)

    def handle_raw_data(self, packet):
        diff = self.dest_packetSize[packet.dest] + packet.size() - self.BLOCK_SIZE
        if diff >= 0:
            self.handle_full_block(packet, diff)
        else:
            self.handle_partial_block(packet)


    def handle_full_block(self, packet, diff):

        dif =  self.BLOCK_SIZE - self.dest_packetSize[packet.dest]
        if dif == packet.size():
            self.dest_packetList[packet.dest].append(tcp_packet.Packet(packet.src, packet.dest, True, packet.is_fin, packet.payload[:dif]))
        else:
            self.dest_packetList[packet.dest].append(tcp_packet.Packet(packet.src, packet.dest, True, False, packet.payload[:dif]))
        self.dest_block[packet.dest] = self.dest_block[packet.dest] + packet.payload[:dif]
        hash = utils.get_hash(self.dest_block[packet.dest])
        if hash in self.hash_packetList.keys():
            comp_packet = tcp_packet.Packet(packet.src, packet.dest, False, packet.is_fin, hash)
            self.send(comp_packet, self.wan_port)
        else:
            self.hash_packetList[hash] = self.dest_packetList[packet.dest]
            self.send_code(packet, self.dest_packetList[packet.dest])
        self.dest_packetSize[packet.dest] = diff

        self.dest_block[packet.dest] = ""
        self.dest_packetList[packet.dest] = []
        if diff != 0:
            self.dest_block[packet.dest] = packet.payload[dif:]
            self.dest_packetList[packet.dest].append(tcp_packet.Packet(packet.src, packet.dest, True, packet.is_fin, packet.payload[dif:]))

    def handle_partial_block(self, packet):
        self.dest_packetSize[packet.dest] += packet.size()
        self.dest_block[packet.dest] += packet.payload
        self.dest_packetList[packet.dest].append(packet)
        if packet.is_fin:
            # lets send what we have so far
            hash = utils.get_hash(self.dest_block[packet.dest])
            if hash in self.hash_packetList:
                comp_packet = tcp_packet.Packet(packet.src, packet.dest, False, False, hash)
                self.send(comp_packet, self.wan_port)
            else:
                self.hash_packetList[hash] = self.dest_packetList[packet.dest]
                self.send_code(packet, self.dest_packetList[packet.dest])
            self.initializer(packet, True)

    def send_code(self, packet, packet_lst):
        # Send the packets in the block
        for p in packet_lst:
            comp_packet = tcp_packet.Packet(packet.src, packet.dest, p.is_raw_data, p.is_fin, p.payload)
            if packet.dest in self.address_to_port:
                # Sending to the clients connected to this middlebox
                self.send(comp_packet, self.address_to_port[comp_packet.dest])
            else:
                # sending thru the WAN.
                self.send(comp_packet, self.wan_port)

