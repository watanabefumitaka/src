# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import logging

from ryu.base import app_manager
from ryu.controller import handler
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.exception import OFPUnknownVersion
from ryu.lib import hub
from ryu.lib.dpid import dpid_to_str
from ryu.lib.packet import bpdu
from ryu.lib.packet import ethernet
from ryu.lib.packet import llc
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_0
#TODO:
#from ryu.ofproto import ofproto_v1_2


UINT16_MAX = 0xffff
UINT32_MAX = 0xffffffff


#TODO: comment
""" STP library uses priority='PRIORITY_BPDU_PACKETIN'
    for packet in of BPDU. So you have to use priority
    larger than 'PRIORITY_BPDU_PACKETIN' for other flow.""" 
PRIORITY_BPDU_PACKETIN = 0

#TODO: interval time
SEND_BPDU_INTERVAL = 10


class Stp(app_manager.RyuApp):

    # TODO: ofproto_v1_2.OFP_VERSION
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    _BRIDGE_LIST = {}

    def __init__(self):
        super(Stp, self).__init__()
        self.name = 'stp'
        self._set_logger()

    def _set_logger(self):
        self.logger.propagate = False
        hdlr = logging.StreamHandler()
        fmt_str = '[STP][%(levelname)s] switch_id=%(sw_id)s: %(message)s'
        hdlr.setFormatter(logging.Formatter(fmt_str))
        self.logger.addHandler(hdlr)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                 [handler.MAIN_DISPATCHER, handler.DEAD_DISPATCHER])
    def dispacher_change(self, ev):
        assert ev.datapath is not None
        if ev.state == handler.MAIN_DISPATCHER:
            self._register_bridge(ev.datapath)
        elif ev.state == handler.DEAD_DISPATCHER:
            self._unregister_bridge(ev.datapath)

    def _register_bridge(self, dp):
        dpid = {'sw_id': dpid_to_str(dp.id)}
        try:
            bridge = Bridge(dp, self.logger)
        except OFPUnknownVersion as message:
            self.logger.error(str(message), extra=dpid)
            return
        self._BRIDGE_LIST.setdefault(dp.id, bridge)
        self.logger.info('Join as stp bridge.', extra=dpid)

    def _unregister_bridge(self, dp):
        if dp.id in self._BRIDGE_LIST:
            self._BRIDGE_LIST[dp.id].send_root_bpdu_stop()
            del self._BRIDGE_LIST[dp.id]
            self.logger.info('Leave stp bridge.',
                             extra={'sw_id': dpid_to_str(dp.id)})

    @set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        if ev.msg.datapath.id in self._BRIDGE_LIST:
            bridge = self._BRIDGE_LIST[ev.msg.datapath.id]
            bridge.packet_in_handler(ev.msg)


class Bridge(object):
    def __init__(self, dp, logger):
        super(Bridge, self).__init__()
        self.dp = dp
        self.logger = logger
        self.ofctl = OfCtl.factory(dp)

        #TODO: priority? mac_address?
        self.bridge_id = BridgeId(bpdu.DEFAULT_BRIDGE_PRIORITY, 0,
                                  dp.ports.values()[0].hw_addr)
        self.root_id = self.bridge_id
        self.ports = Ports(dp.ports.values(), self.root_id)

        # Set BPDU packet in flow.
        self.ofctl.set_bpdu_packetin_flow()
        self.logger.info('Set BPDU packet in flow',
                         extra={'sw_id': dpid_to_str(self.dp.id)}) 

        # Start cyclic send root BPDU packet.
        self._send_root_bpdu_start()

    def _send_root_bpdu_start(self):
        self.is_root = True
        self.thread = hub.spawn(self._cyclic_send_root_bpdu)
        self.logger.info('Start cyclic send root BPDU packet.',
                         extra={'sw_id': dpid_to_str(self.dp.id)})            

    def send_root_bpdu_stop(self):
        if self.is_root:
            self.is_root = False
            hub.joinall([self.thread])
            self.logger.info('Stop cyclic send root BPDU packet.',
                             extra={'sw_id': dpid_to_str(self.dp.id)})     

    def _cyclic_send_root_bpdu(self):
        # TODO: root_path_cost? message_age?
        root_path_cost = 0
        message_age = 1
        while self.is_root:
            # Send BPDU except blocking port.
            for port in self.ports.non_blocking_ports():
                self.ofctl.send_bpdu(self.root_id, root_path_cost,
                                     self.bridge_id, port,
                                     message_age)
                #hub.sleep(1)
            hub.sleep(SEND_BPDU_INTERVAL)

    def packet_in_handler(self, msg):
        pkt = packet.Packet(msg.data)
        if bpdu.ConfigurationBPDUs in pkt:
            (bpdu_pkt, ) = pkt.get_protocols(bpdu.ConfigurationBPDUs)
            root_id = bpdu.ConfigurationBPDUs.encode_bridge_id(
                bpdu_pkt.root_priority, bpdu_pkt.root_system_id_extension,
                bpdu_pkt.root_mac_address)

            #TODO: OFPv1.2 in_port is different.
            if self._has_roop(msg.in_port, root_id):
                #TODO: block port.
                print 'roop!'
                pass
            else:
                print 'no roop!'
                self._compare_root_id(msg.in_port, root_id, bpdu_pkt)

        elif bpdu.RstBPDUs in pkt:
            #TODO: RSTP
            pass

    def _has_roop(self, in_port, root_id):
        ports = self.ports.get_port(self.root_id)
        assert len(ports) <= 1
        return bool(ports and ports[0].port_no != in_port)

    def _compare_root_id(self, in_port, root_id, bpdu_pkt):

        if root_id <= self.root_id.value:  #TODO: if same?
            self.send_root_bpdu_stop()
            self.root_id = BridgeId(bpdu_pkt.root_priority,
                                    bpdu_pkt.root_system_id_extension,
                                    bpdu_pkt.root_mac_address)
            self.ports[in_port].root_id = self.root_id

            # TODO: root_path_cost? message_age?
            message_age = 1
            for port in self.ports.non_blocking_ports():
                if self.ports[in_port].port_no != port.port_no:
                    root_path_cost = bpdu_pkt.root_path_cost + port.cost
                    self.ofctl.send_bpdu(self.root_id, root_path_cost,
                                         self.bridge_id, port,
                                         message_age)

class BridgeId(object):
    def __init__(self, priority, system_id_extension, mac_addr):
        super(BridgeId, self).__init__()
        self.priority = priority
        self.system_id_extension = system_id_extension
        self.mac_addr = mac_addr
        self.value = bpdu.ConfigurationBPDUs.encode_bridge_id(
            priority, self.system_id_extension, mac_addr)


class Ports(dict):
    def __init__(self, ports, root_id):
        super(Ports, self).__init__()
        #TODO: bpdu.py
        BPDU_MAX_PORT_NO = 0xfff
        for port in ports:
            if port.port_no <= BPDU_MAX_PORT_NO:
                port_data = Port(port.port_no, port.hw_addr, root_id)
                self[port.port_no] = port_data

    def non_blocking_ports(self):
        return [port for port in self.values() if not port.is_block]

    def get_port(self, root_id):
        return [port for port in self.values()
                if port.root_id.value == root_id]


class Port(object):
    def __init__(self, port_no, mac_addr, root_id):
        super(Port, self).__init__()
        self.priority = bpdu.DEFAULT_PORT_PRIORITY
        self.port_no = port_no
        self.port_id = bpdu.ConfigurationBPDUs.encode_port_id(self.priority,
                                                              port_no)
        self.mac_addr = mac_addr
        self.cost = 10  #TODO: cost?
        self.is_block = False
        self.root_id = root_id


class OfCtl(object):

    _OF_VERSIONS = {}

    @staticmethod
    def register_of_version(version):
        def _register_of_version(cls):
            OfCtl._OF_VERSIONS.setdefault(version, cls)
            return cls
        return _register_of_version

    @staticmethod
    def factory(dp):
        of_version = dp.ofproto.OFP_VERSION
        if of_version in OfCtl._OF_VERSIONS:
            return OfCtl._OF_VERSIONS[of_version](dp)
        else:
            raise OFPUnknownVersion(version=of_version)

    def __init__(self, dp):
        super(OfCtl, self).__init__()
        self.dp = dp


@OfCtl.register_of_version(ofproto_v1_0.OFP_VERSION)
class OfCtl_v1_0(OfCtl):

    def __init__(self, dp):
        super(OfCtl_v1_0, self).__init__(dp)

    def set_bpdu_packetin_flow(self):
        ofp_parser = self.dp.ofproto_parser
        cookie = 0
        cmd = self.dp.ofproto.OFPFC_ADD

        wildcards = self.dp.ofproto.OFPFW_ALL
        wildcards &= ~self.dp.ofproto.OFPFW_DL_DST
        dl_dst = bpdu.BRIDGE_GROUP_ADDRESS
        match = ofp_parser.OFPMatch(wildcards, 0, 0, dl_dst, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0)

        miss_send_len = UINT16_MAX
        actions = [self.dp.ofproto_parser.OFPActionOutput(
            self.dp.ofproto.OFPP_CONTROLLER, miss_send_len)]

        m = ofp_parser.OFPFlowMod(self.dp, match, cookie, cmd,
                                  priority=PRIORITY_BPDU_PACKETIN,
                                  actions=actions)
        self.dp.send_msg(m)

    def send_bpdu(self, root_id, root_path_cost, bridge_id, port_id,
                  message_age):
                  #TODO: flags? root_system_id_extension?
                  #      bridge_system_id_extension?
                  #      max_age? hello_time? forward_delay?
        # Generate BPDU packet
        src_mac = port_id.mac_addr
        dst_mac = bpdu.BRIDGE_GROUP_ADDRESS
        length = bpdu.ConfigurationBPDUs.PACK_LEN + \
                 llc.llc._PACK_LEN + llc.ControlFormatU._PACK_LEN

        pkt = packet.Packet()
        e = ethernet.ethernet(dst_mac, src_mac, length)
        l = llc.llc(llc.SAP_BDPU, llc.SAP_BDPU, llc.ControlFormatU())
        b = bpdu.ConfigurationBPDUs(root_priority=root_id.priority,
                                    root_mac_address=root_id.mac_addr,
                                    root_path_cost=root_path_cost,
                                    bridge_priority=bridge_id.priority,
                                    bridge_mac_address=bridge_id.mac_addr,
                                    port_priority=port_id.priority,
                                    port_number=port_id.port_no,
                                    message_age=message_age)
        pkt.add_protocol(e)
        pkt.add_protocol(l)
        pkt.add_protocol(b)
        pkt.serialize()

        output = port_id.port_no
        actions = [self.dp.ofproto_parser.OFPActionOutput(output, 0)]
        self.dp.send_packet_out(buffer_id=UINT32_MAX,
                                in_port=self.dp.ofproto.OFPP_CONTROLLER,
                                actions=actions, data=pkt.data)
