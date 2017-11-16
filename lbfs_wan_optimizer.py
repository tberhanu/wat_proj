
import utils
import tcp_packet
import collections
import wan_optimizer


class WanOptimizer(wan_optimizer.BaseWanOptimizer):
    """ WAN Optimizer that divides data into variable-sized
    blocks based on the contents of the file.
    This WAN optimizer should implement part 2 of project 4.
    """

    # The string of bits to compare the lower order 13 bits of hash to
    GLOBAL_MATCH_BITSTRING = '0111011001010'

    def __init__(self):
        wan_optimizer.BaseWanOptimizer.__init__(self)
        # Add any code that you like here (but do not add any constructor arguments).
        self.hash_payloads = {}
        self.srcDest_payloads = collections.defaultdict(str)

    def receive(self, packet):
        if packet.dest in self.address_to_port:
            self.handle_directly(packet)
        else:
            self.handle_indirectly(packet)

    def handle_directly(self, packet):
        # packet to the client that directly connected with this middlebox
        srcDest = packet.src + packet.dest
        if packet.is_raw_data:
            self.srcDest_payloads[srcDest] += packet.payload
            diff = len(self.srcDest_payloads[srcDest]) - 48
            hash = utils.get_hash(self.srcDest_payloads[srcDest][diff:])
            last_n_bits = utils.get_last_n_bits(hash, 13)

            if packet.is_fin or len(self.srcDest_payloads[srcDest]) >= 48 and last_n_bits == self.GLOBAL_MATCH_BITSTRING:

                hash = utils.get_hash(self.srcDest_payloads[srcDest])
                self.hash_payloads[hash] = self.srcDest_payloads[srcDest]
                self.send_code(packet, self.address_to_port[packet.dest], self.srcDest_payloads[srcDest])
                self.srcDest_payloads[srcDest] = ""
        else:
            self.srcDest_payloads[srcDest] = ""
            self.send_code(packet, self.address_to_port[packet.dest], self.hash_payloads[packet.payload])

    def handle_indirectly(self, packet):
        # packet indirectly to a client thru another middlebox
        if packet.is_raw_data:
            srcDest = packet.src + packet.dest
            self.srcDest_payloads[srcDest] += packet.payload

            if len(self.srcDest_payloads[srcDest]) > 48:
                start = 0
                diff = len(self.srcDest_payloads[srcDest]) - packet.size()
                end = max(48, diff)
                while end <= len(self.srcDest_payloads[srcDest]):
                    hash = utils.get_hash(self.srcDest_payloads[srcDest][end - 48:end])
                    last_n_bits = utils.get_last_n_bits(hash, 13)
                    if last_n_bits == self.GLOBAL_MATCH_BITSTRING:
                        hash = utils.get_hash(self.srcDest_payloads[srcDest][start:end])
                        self.send_code(packet, self.wan_port, self.srcDest_payloads[srcDest][start:end], key=hash)

                        self.srcDest_payloads[srcDest] = self.srcDest_payloads[srcDest][end:]
                        start = end
                        end += 48
                    else:
                        end += 1
            if packet.is_fin:
                if len(self.srcDest_payloads[srcDest]) > 0:
                    hash = utils.get_hash(self.srcDest_payloads[srcDest])
                    self.send_code(packet, self.wan_port, self.srcDest_payloads[srcDest], key=hash)
                else:
                    self.send_code(packet, self.wan_port, self.srcDest_payloads[srcDest])
                self.srcDest_payloads[srcDest] = ""
        else:
            self.send(packet, self.wan_port)

    def send_code(self, packet, dest, payload, key=None):
        if key and self.hash_payloads.has_key(key):
            self.send(tcp_packet.Packet(packet.src, packet.dest, False, packet.is_fin, key), dest)
        else:
            if key and not self.hash_payloads.has_key(key):
                self.hash_payloads[key] = payload

            while (len(payload) > utils.MAX_PACKET_SIZE):
                p = tcp_packet.Packet(packet.src, packet.dest, True, False, payload[:utils.MAX_PACKET_SIZE])
                payload = payload[utils.MAX_PACKET_SIZE:]
                self.send(p, dest)
            packet = tcp_packet.Packet(packet.src, packet.dest, True, packet.is_fin, payload)
            self.send(packet, dest)