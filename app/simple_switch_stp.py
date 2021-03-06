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

import struct

from ryu.base import app_manager
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib import dpid as dpid_lib
from ryu.lib.mac import haddr_to_str

#TODO:
#from ryu.lib import stplib
import stplib


#TODO: delete
STP_CONFIG = {dpid_lib.str_to_dpid('0000000000000001'):
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
                             'enable': True}}},

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
                             'enable': True}}},

              dpid_lib.str_to_dpid('0000000000000003'):
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
                             'enable': True}}},
              dpid_lib.str_to_dpid('0000000000000004'):
              {'bridge': {'priority': 0xb000}}}


class SimpleSwitchStp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    _CONTEXTS = {'stplib': stplib.Stp}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchStp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.stp = kwargs['stplib']

        # Sample of stplib config
        #  - please refer to stplib.Stp.set_config() for details.
        """
        config = {dpid_lib.str_to_dpid('0000000000000001'):
                     {'bridge': {'priority': 0x8000,
                                 'max_age': 10},
                      'ports': {1: {'priority': 0x80},
                                2: {'priority': 0x90}}},
                  dpid_lib.str_to_dpid('0000000000000002'):
                     {'bridge': {'priority': 0x9000}}}
        self.stp.set_config(config)
        """
        self.stp.set_config(STP_CONFIG)  #TODO: delete

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

    @set_ev_cls(stplib.EventPacketIn, stplib.STP_EV_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        dst, src, _eth_type = struct.unpack_from('!6s6sH', buffer(msg.data), 0)

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.debug("packet in %s %s %s %s",
                          dpid, haddr_to_str(src), haddr_to_str(dst),
                          msg.in_port)

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

    @set_ev_cls(stplib.EventTopologyChange, stplib.STP_EV_DISPATCHER)
    def _topology_change_handler(self, ev):
        dp = ev.dp
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        msg = 'Receive topology change event. Flush MAC table.'
        self.logger.debug("[dpid=%s] %s", dpid_str, msg)

        if dp.id in self.mac_to_port:
            del self.mac_to_port[dp.id]
        self.delete_flow(dp)

    @set_ev_cls(stplib.EventPortStateChange, stplib.STP_EV_DISPATCHER)
    def _port_state_change_handler(self, ev):
        dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
        of_state = {ofproto_v1_0.OFPPS_LINK_DOWN: 'DISABLE',
                    ofproto_v1_0.OFPPS_STP_BLOCK: 'BLOCK',
                    ofproto_v1_0.OFPPS_STP_LISTEN: 'LISTEN',
                    ofproto_v1_0.OFPPS_STP_LEARN: 'LEARN',
                    ofproto_v1_0.OFPPS_STP_FORWARD: 'FORWARD'}
        self.logger.debug("[dpid=%s][port=%d] state=%s",
                          dpid_str, ev.port_no, of_state[ev.port_state])
