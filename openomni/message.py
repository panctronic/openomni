import crc16
from packet import Packet, PacketType
from commands import COMMAND_TYPES, UnknownCommand


class Message(object):
    def __init__(self, packet=None):
        self._packets = []
        self.add_packet(packet)

    def add_packet(self, packet=None):
        if packet and self._packets and packet.packet_type != PacketType.CON:
            raise TypeError('Cannot add %s to existing message' % packet.packet_type)
        self._packets.append(packet)
        return self

    @property
    def data(self):
        return ''.join(p.data[5:-1] for p in self._packets)
        
    @property
    def pod_address(self):
        return self.data[:4].encode('hex')
    
    @property
    def byte9(self):
        return ord(self.data[4])
    
    @property
    def body_len(self):
        return ord(self.data[5])
    
    @property
    def body(self):
        return self.data[6:-2]

    @property 
    def crc(self):
        return self.data[-2:]

    def is_complete(self):
        return (len(self.body) == self.body_len
                and self.crc == self.computed_crc_bytes())

    def data_for_crc(self):
        data = self.pod_address.decode('hex')
        data += chr(self.byte9)
        data += chr(len(self.body))
        data += self.body
        return data

    def computed_crc(self):
        return crc16.calc(self.data_for_crc())

    def computed_crc_bytes(self):
        crc = self.computed_crc()
        return chr(crc >> 8) + chr(crc & 0xff)

    def commands(self):
        cmd_idx = 0
        cmds = []
        while cmd_idx < len(self.body)-1:
            cmd_type = ord(self.body[cmd_idx])
            cmd_len = ord(self.body[cmd_idx+1])
            cmd_class = COMMAND_TYPES.get(cmd_type, UnknownCommand)
            cmds.append(cmd_class(self.body[cmd_idx+2:cmd_idx+2+cmd_len], cmd_type, cmd_len))
            cmd_idx += cmd_len + 2

        return cmds

    def packetize(self, start_sequence):
        body_remaining = self.body + self.computed_crc_bytes()
        packets = []
        while len(body_remaining) > 0:
            packet = Packet()
            packet.pod_address_1 = self.pod_address
            packet.sequence = start_sequence + len(packets) * 2
            if len(packets) == 0:
                packet.packet_type = PacketType.PDM
                packet.pod_address_2 = self.pod_address
                packet.byte9 = self.byte9
                segment_len = min(Packet.MAX_BODY_SEGMENT_LEN,len(body_remaining))
                packet.body = body_remaining[:segment_len]
                packet.body_len = len(self.body)
                body_remaining = body_remaining[segment_len:]
            else:
                packet.packet_type = PacketType.CON
                segment_len = min(Packet.MAX_CON_BODY_SEGMENT_LEN,len(body_remaining))
                packet.body = body_remaining[:segment_len]
                body_remaining = body_remaining[segment_len:]

            packets.append(packet)

        return packets
        

class MessageBuilder(object):
    def __init__(self):
        self._pending = None
        self._i = None
    
    def increment(self, val):
        if val > self._i or self._i is None or self._i == 31:
            self._i = val
            return True
            

    def add_packet(self, packet):
        if not self.increment(packet.sequence):
            print('skipping out of sequence')
        elif packet.packet_type in (PacketType.PDM, PacketType.POD):
            m = Message(packet)
            if not m.is_complete():
                print('store')
                self._pending = m
            else:
                return m
        elif packet.packet_type == PacketType.CON:
            
            if self._pending:
                print('continue')
                m = self._pending.add_packet(packet)
                if self._pending.is_complete():
                    self._pending = None
                    return m


      
        
