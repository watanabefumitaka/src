# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import struct

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib import dpid as dpid_lib
from ryu.lib.mac import haddr_to_str

#TODO:
#from ryu.lib import stp_lib
import stp_lib


# TODO: we should split the handler into two parts, protocol
# independent and dependant parts.

# TODO: can we use dpkt python library?

# TODO: we need to move the followings to something like db


# Sample of stp_lib config
#  - please refer to stp_lib.Stp.set_config() for details.
STP_CONFIG = {dpid_lib.str_to_dpid('0000000000000001'):
               {'bridge': {'priority': 0x8000,
                           'max_age': 20,
                           'hello_time': 2,
                           'fwd_delay': 15},
                'ports': {1: {'priority': 0x80,
                              'path_cost': 20,
                              'enable': True},
                          2: {'priority': 0x80,
                              'path_cost': 20,
                              'enable': True},
                          3: {'priority': 0x80,
                              'path_cost': 20,
                              'enable': True},}},

              dpid_lib.str_to_dpid('0000000000000002'):
               {'bridge': {'priority': 0x9000,
                           'max_age': 20,
                           'hello_time': 2,
                           'fwd_delay': 15},
                'ports': {1: {'priority': 0x80,
                              'path_cost': 20,
                              'enable': True},
                          2: {'priority': 0x80,
                              'path_cost': 20,
                              'enable': True},
                          3: {'priority': 0x80,
                              'path_cost': 20,
                              'enable': True},}},

              dpid_lib.str_to_dpid('0000000000000003'):
               {'bridge': {'priority': 0xa000,
                           'max_age': 20,
                           'hello_time': 2,
                           'fwd_delay': 15},
                'ports': {1: {'priority': 0x80,
                              'path_cost': 20,
                              'enable': True},
                          2: {'priority': 0x80,
                              'path_cost': 20,
                              'enable': True},
                          3: {'priority': 0x80,
                              'path_cost': 20,
                              'enable': True},}},}


class SimpleSwitchStp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    _CONTEXTS = {'stp_lib': stp_lib.Stp}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchStp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.stp = kwargs['stp_lib']
        self.stp.set_config(STP_CONFIG)

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        wildcards = ofproto_v1_0.OFPFW_ALL
        wildcards &= ~ofproto_v1_0.OFPFW_IN_PORT
        wildcards &= ~ofproto_v1_0.OFPFW_DL_DST

        match = datapath.ofproto_parser.OFPMatch(
            wildcards, in_port, 0, dst,
            0, 0, 0, 0, 0, 0, 0, 0, 0)

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    def delete_flow(self, datapath):
        ofproto = datapath.ofproto

        wildcards = ofproto_v1_0.OFPFW_ALL
        match = datapath.ofproto_parser.OFPMatch(
            wildcards, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_DELETE)
        datapath.send_msg(mod)

    @set_ev_cls(stp_lib.EventPacketIn, stp_lib.STP_EV_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        dst, src, _eth_type = struct.unpack_from('!6s6sH', buffer(msg.data), 0)

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        #TODO:
        #self.logger.info("packet in %s %s %s %s",
        #                 dpid, haddr_to_str(src), haddr_to_str(dst),
        #                 msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst, actions)

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no
        dp = msg.datapath
        ofproto = dp.ofproto

        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)

    @set_ev_cls(stp_lib.EventTopologyChange, stp_lib.STP_EV_DISPATCHER)
    def _topology_change_handler(self, ev):
        dp = ev.dp
        self.logger.debug("[dpid=%s] Receive topology change event.",
                          dpid_lib.dpid_to_str(dp.id))
        if dp.id in self.mac_to_port:
            del self.mac_to_port[dp.id]
        self.delete_flow(dp)
