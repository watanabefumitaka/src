from ryu.lib.packet import packet
from ryu.lib.packet import bpdu
from ryu.lib.packet import llc


data = ('\x01\x80\xc2\x00\x00\x00\x00\x1c\x0e\x87\x85\x04\x00\x26\x42'
        '\x42\x03\x00\x00\x00\x00\x00\x80\x64\x00\x1c\x0e\x87\x78\x00'
        '\x00\x00\x00\x04\x80\x64\x00\x1c\x0e\x87\x85\x00\x80\x04\x01'
        '\x00\x14\x00\x02\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        

pkt = packet.Packet(data)
print pkt
print ''


"""
data = "\x00\x00\x00\x00\x00\x80\x64\x00\x1c\x0e\x87\x78\x00\x00\x00\x00\x04\x80\x64\x00\x1c\x0e\x87\x85\x00\x80\x04\x01\x00\x14\x00\x02\x00\x0f\x00"
bp = bpdu.bpdu.parser(data)
print bp
print ''



#cfg = bpdu.ConfigurationBPDUs(flags, root_id, root_path_cost, bridge_id, port_id,
#                              message_age, max_age, hello_time, forward_delay)
cfg = bpdu.ConfigurationBPDUs(root_system_id_extension=200, port_number=350)
data = cfg.serialize(None, None)


bp = bpdu.bpdu.parser(data)
print bp
print ''


topo = bpdu.TopologyChangeNotificationBPDUs()
data = topo.serialize(None, None)


bp = bpdu.bpdu.parser(data)
print bp
print ''



#rst = bpdu.RstBPDUs(flags, root_id, root_path_cost, bridge_id, port_id,
#                    message_age, max_age, hello_time, forward_delay)
rst = bpdu.RstBPDUs(flags = 0b11111111, root_system_id_extension=200)
data = rst.serialize(None, None)
bp = bpdu.bpdu.parser(data)
print bp


"""

"""
#dsap_addr = 0b1000011
dsap_addr = 0x42
ssap_addr = 0b1000011
pf_bit = 1
control = llc.ControlFormatI(0b1111111, pf_bit, 0b1101010)

ll = llc.llc(dsap_addr, ssap_addr, control)
data = ll.serialize(None, None)

ll = llc.llc.parser(data)
print ll
print ''


control = llc.ControlFormatS(0b10, pf_bit, 0b1101010)

ll = llc.llc(dsap_addr, ssap_addr, control)
data = ll.serialize(None, None)

ll = llc.llc.parser(data)
print ll
print ''


control = llc.ControlFormatU(0b00, pf_bit, 0b111)

ll = llc.llc(dsap_addr, ssap_addr, control)
data = ll.serialize(None, None)

ll = llc.llc.parser(data)
print ll
print ''

"""
