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
from ryu.controller import event
from ryu.controller import handler
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.exception import OFPUnknownVersion
from ryu.lib import addrconv
from ryu.lib import hub
from ryu.lib.dpid import dpid_to_str
from ryu.lib.packet import bpdu
from ryu.lib.packet import ethernet
from ryu.lib.packet import llc
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_0


STP_EV_DISPATCHER = "stp"


UINT32_MAX = 0xffffffff

MAX_PORT_NO = 0xfff

# Port role
ROOT_PORT = 0
DESIGNATED_PORT = 1
NON_DESIGNATED_PORT = 2

# Port state
PORT_STATE_DISABLE = ofproto_v1_0.OFPPC_NO_STP
PORT_STATE_BLOCKING = (ofproto_v1_0.OFPPC_NO_RECV
                       | ofproto_v1_0.OFPPC_NO_FLOOD
                       | ofproto_v1_0.OFPPC_NO_FWD)
PORT_STATE_LISTENING = (ofproto_v1_0.OFPPC_NO_RECV
                        | ofproto_v1_0.OFPPC_NO_FLOOD)
PORT_STATE_LEARNING = ofproto_v1_0.OFPPC_NO_FLOOD
PORT_STATE_FORWARDING = 0


#DEFAULT_TRANSMIT_HOLD_COUNT = 6


# Flush filtering database, when you receive this event.
class EventTopologyChange(event.EventBase):
    def __init__(self, dp):
        super(EventTopologyChange, self).__init__()
        self.dp = dp


# Throw this event when port status is LEARNING or FORWARDING.
class EventPacketIn(event.EventBase):
    def __init__(self, msg):
        super(EventPacketIn, self).__init__()
        self.msg = msg


def equal(value1, value2):
    for key in value1.__dict__.keys():
        if (not hasattr(value2, key)
                or getattr(value1, key) != getattr(value2, key)):
            return False
    return True


class Stp(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    _BRIDGE_LIST = {}

    def __init__(self):
        super(Stp, self).__init__()
        self.name = 'stp'
        self._set_logger()

    def close(self):
        [self._unregister_bridge(dpid) for dpid in self._BRIDGE_LIST.keys()]

    def _set_logger(self):
        self.logger.propagate = False
        hdlr = logging.StreamHandler()
        fmt_str = '[STP][%(levelname)s] dpid=%(dpid)s: %(message)s'
        hdlr.setFormatter(logging.Formatter(fmt_str))
        self.logger.addHandler(hdlr)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [handler.MAIN_DISPATCHER, handler.DEAD_DISPATCHER])
    def dispacher_change(self, ev):
        assert ev.datapath is not None
        if ev.state == handler.MAIN_DISPATCHER:
            self._register_bridge(ev.datapath)
        elif ev.state == handler.DEAD_DISPATCHER:
            self._unregister_bridge(ev.datapath.id)

    def _register_bridge(self, dp):
        dpid = {'dpid': dpid_to_str(dp.id)}
        try:
            bridge = Bridge(dp, self.logger,
                            self.send_event_to_observers)
        except OFPUnknownVersion as message:
            self.logger.error(str(message), extra=dpid)
            return
        self._BRIDGE_LIST.setdefault(dp.id, bridge)
        self.logger.info('Join as stp bridge.', extra=dpid)

    def _unregister_bridge(self, dp_id):
        if dp_id in self._BRIDGE_LIST:
            self._BRIDGE_LIST[dp_id].delete()
            del self._BRIDGE_LIST[dp_id]
            self.logger.info('Leave stp bridge.',
                             extra={'dpid': dpid_to_str(dp_id)})

    @set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        if ev.msg.datapath.id in self._BRIDGE_LIST:
            bridge = self._BRIDGE_LIST[ev.msg.datapath.id]
            bridge.packet_in_handler(ev.msg)


class Bridge(object):
    def __init__(self, dp, logger, send_ev_func):
        super(Bridge, self).__init__()
        self.dp = dp
        self.logger = logger
        self.dpid_str = {'dpid': dpid_to_str(dp.id)}
        self.send_event = send_ev_func

        # Bridge data
        system_id = addrconv.mac.bin_to_text(dp.ports.values()[0].hw_addr)
        self.bridge_id = BridgeId(bpdu.DEFAULT_BRIDGE_PRIORITY,  #TODO: config
                                  0,                             #TODO: systemExtension
                                  system_id)
        self.bridge_times = Times(10,                            #TODO: config
                                  bpdu.DEFAULT_MAX_AGE,          #TODO: config
                                  bpdu.DEFAULT_HELLO_TIME,       #TODO: config
                                  bpdu.DEFAULT_FORWARD_DELAY)    #TODO: config
        # Ports
        self.ports = {}
        for port_data in dp.ports.values():
            if port_data.port_no <= MAX_PORT_NO:
                self.ports[port_data.port_no] = Port(dp, logger,
                                                     send_ev_func,
                                                     self.bridge_id,
                                                     port_data)
        self._init_spanning_tree()

    @property
    def is_root_bridge(self):
        assert self.ports.values()[0]
        port = self.ports.values()[0]
        return bool(self.bridge_id.value == port.root_id.value)

    @property
    def xxx_timer(self):  # TODO: method_name
        assert self.ports.values()[0]
        port = self.ports.values()[0]
        return port.root_times.max_age + port.root_times.forward_delay

    def _init_spanning_tree(self):
        self.delete()
        [port.init(self.bridge_times) for port in self.ports.values()]

    def delete(self):
        [port.delete() for port in self.ports.values()]

    def packet_in_handler(self, msg):
        if not msg.in_port in self.ports:
            return

        pkt = packet.Packet(msg.data)
        in_port = self.ports[msg.in_port]

        if bpdu.ConfigurationBPDUs in pkt:
            """ Receive Configuration BPDU.
                 - Check message age.
                 - Update port receive data.
                 - If update, restructure of spanning tree
                    and send Topology Change Notification BPDU.
                 - If receive Topology Change BPDU,
                    send EventTopologyChange, and change port status
                    to Listening each port which status is Blocking. """
            (bpdu_pkt, ) = pkt.get_protocols(bpdu.ConfigurationBPDUs)
            if bpdu_pkt.message_age > bpdu_pkt.max_age:
                log_msg = 'Drop BPDU packet which message_age exceeded.'
                self.logger.debug(log_msg, extra=self.dpid_str)
                return

            is_update, is_tc = in_port.rcv_config_bpdu(bpdu_pkt)
            #TODO: relation of is_update & is_rcv_tc
            if is_update:
                self._init_spanning_tree()
                self._spanning_tree_algorithm(in_port, bpdu_pkt)
                self._transmit_tcn_bpdu()
            if is_tc:
                self.send_event(EventTopologyChange(self.dp))
                [port.rcv_tc_bpdu() for port in self.ports.values()]

        elif bpdu.TopologyChangeNotificationBPDUs in pkt:
            """ Receive Topology Change Notification BPDU.
                 - Throw EventTopologyChange
                 - Send Topology Change Ack BPDU.
                 - If root bridge, send Topology Change BPDU.
                   Else, send Topology Change Notification BPDU. """
            self.send_event(EventTopologyChange(self.dp))
            in_port.transmit_ack_bpdu()
            if self.is_root_bridge:
                [hub.spawn(port.transmit_tc_bpdu)
                 for port in self.port.values()]
            else:
                self._transmit_tcn_bpdu()

        elif bpdu.RstBPDUs in pkt:
            """ Receive Rst BPDU. """
            #TODO:
            pass
        else:
            """ Receive non BPDU packet.
                 - Throw EventPacketIn. """
            self.send_event(EventPacketIn(msg))

    def _spanning_tree_algorithm(self, in_port, bpdu_pkt):
        """ 1. Select root bridge.
            2. Update tree roles. """
        self._select_root_bridge()
        self._update_tree_roles(in_port, bpdu_pkt)

    def _select_root_bridge(self):
        """ Select most superior bridge as a root bridge."""
        root_port = None
        for port in self.ports.values():
            if port.port_priority is None:
                continue
            if (not root_port or (port.port_priority.value
                                  < root_port.port_priority.value)):
                root_port = port

        # Update root bridge data
        for port in self.ports.values():
            port.root_id = root_port.port_priority
            port.root_path_cost = root_port.port_path_cost
            port.root_times = root_port.port_times

    def _update_tree_roles(self, in_port, bpdu_pkt):
        """ Root bridge: All port is set to DesignatedPort.
            Non root bridge: Select one RootPort and some DesignatedPort,
             and the other port is set to NonDesignatedPort. """
        root_port = None

        if self.is_root_bridge:
            #TODO:
            print '[%s] Root bridge.' % self.dpid_str['dpid']
            # Root bridge
            for port in self.ports.values():
                port.role = DESIGNATED_PORT
        else:
            #TODO:
            print '[%s] Non root bridge.' % self.dpid_str['dpid']
            # Non root bridge
            for port in self.ports.values():
                port.role = NON_DESIGNATED_PORT
            root_port = self._select_root_port(in_port)
            self._select_designated_port(root_port)

        return root_port

    def _select_root_port(self, in_port):
        """ Root port is the port nearest to a root bridge. """
        root_port = in_port

        for port in self.ports.values():
            if (port.port_priority is None
                    or port.port_priority.value != in_port.port_priority.value
                         or port.state is PORT_STATE_DISABLE):
                continue
            if self._is_superior_root_path(port.port_path_cost,
                                           root_port.port_path_cost,
                                           port.designated_bridge_id,
                                           root_port.designated_bridge_id,
                                           port.port_id,
                                           root_port.port_id):
                root_port = port
        root_port.role = ROOT_PORT
        return root_port

    def _select_designated_port(self, root_port):
        """ Designated port is the port nearest to a root bridge
             of each link. """
        for port in self.ports.values():
            if (port.state is PORT_STATE_DISABLE
                    or port.data.port_no == root_port.data.port_no):
                continue
            if port.port_priority is None:
                    #or port.port_priority.value != root_port.port_priority.value):
                port.role = DESIGNATED_PORT
                continue

            if self._is_superior_root_path(root_port.port_path_cost,
                                           (port.port_path_cost
                                            - port.path_cost),
                                           self.bridge_id.value,
                                           port.designated_bridge_id,
                                           root_port.port_id,
                                           port.designated_port_id):
                port.role = DESIGNATED_PORT

    def _is_superior_root_path(self, path_cost1, path_cost2,
                               bridge_id1, bridge_id2, port_id1, port_id2):
        """ Compare root path using following priorities.
             [root_path_cost > designated_bridge_id > port_id] """
        if path_cost1 < path_cost2:
            return True
        elif path_cost1 == path_cost2:
            if bridge_id1 < bridge_id2:
                return True
            elif bridge_id1 == bridge_id2:
                if port_id1 < port_id2:
                    return True
        return False

    def _transmit_tcn_bpdu(self):
        root_port = None
        for port in self.ports.values():
            if port.role is ROOT_PORT:
                root_port = port
                break
        if root_port:
            hub.spawn(root_port.transmit_tcn_bpdu)


class Port(object):
    def __init__(self, dp, logger, send_ev_func, bridge_id, data):
        super(Port, self).__init__()
        self.dp = dp
        self.logger = logger
        self.dpid_str = {'dpid': dpid_to_str(dp.id)}
        self.send_event = send_ev_func
        self.ofctl = OfCtl_v1_0(dp)

        # Bridge data
        self.bridge_id = bridge_id
        # Root bridge data
        self.root_id = None
        self.root_path_cost = None
        self.root_times = None

        # ofproto_v1_0_parser.OFPPhyPort data
        self.data = data
        # Port data
        self.priority = bpdu.DEFAULT_PORT_PRIORITY  #TODO: config
        self.path_cost = 10                         #TODO: config
        self.port_id = bpdu.ConfigurationBPDUs.encode_port_id(self.priority,
                                                              data.port_no)
        self.hello_time = bpdu.DEFAULT_HELLO_TIME  # for TCN send time
        # State and Role
        self.state = None
        self.role = None
        # Receive BPDU data
        self.port_priority = None
        self.port_path_cost = None
        self.port_times = None
        self.designated_bridge_id = None
        self.designated_port_id = None
        # TopologyChange message send flags
        self.send_tc_flg = None
        self.send_tcn_flg = None
        # State machine thread
        self.state_machine = None
        self.event = None
        # Send configBPDU thread
        self.send_bpdu_thread = None

    #TODO: method name
    def init(self, root_times):
        self.root_id = self.bridge_id
        self.root_path_cost = 0
        self.root_times = root_times
        self.send_tc_flg = False
        self.send_tcn_flg = False
        # TODO:
        """
        self.port_priority = None
        self.port_path_cost = None
        self.port_times = None
        self.designated_bridge_id = None
        self.designated_port_id = None
        """
        self.send_tc_flg = False

        self.role = DESIGNATED_PORT
        if self.state is not PORT_STATE_DISABLE:  #TODO: config
            self._change_status(PORT_STATE_BLOCKING)

        self.state_machine = hub.spawn(self._state_machine)
        self.send_bpdu_thread = hub.spawn(self._transmit_config_bpdu)
        self.logger.debug(('[port=%d] Start port threads.'
                           % self.data.port_no), extra=self.dpid_str)

    def delete(self):
        threads = []
        if self.state_machine:
            threads.append(self.state_machine)
        if self.send_bpdu_thread:
            threads.append(self.send_bpdu_thread)

        for thread in threads:
            hub.kill(thread)
        hub.joinall(threads)
        self.state_machine = None
        self.send_bpdu_thread = None
        self.logger.debug(('[port=%d] Stop port threads.'
                           % self.data.port_no), extra=self.dpid_str)
        if self.event:
            self.event.set()
            self.event = None

    def rcv_config_bpdu(self, bpdu_pkt):
        # Check TopologyChange flag.
        rcv_tc_flg = False
        tc_flag_mask = 0b00000001
        tcack_flag_mask = 0b10000000
        if bpdu_pkt.flags & tc_flag_mask:
            # receive TopologyChange message
            rcv_tc_flg = True
        if bpdu_pkt.flags & tcack_flag_mask:
            # receive TopologyChangeAck message
            if self.send_tcn_flg:
                self.send_tcn_flg = False

        # Check received BPDU is updated.
        rcv_root_id = BridgeId(bpdu_pkt.root_priority,
                               bpdu_pkt.root_system_id_extension,
                               bpdu_pkt.root_mac_address)
        rcv_root_times = Times(bpdu_pkt.message_age,
                               bpdu_pkt.max_age,
                               bpdu_pkt.hello_time,
                               bpdu_pkt.forward_delay)
        rcv_bridge_id = bpdu.ConfigurationBPDUs.encode_bridge_id(
            bpdu_pkt.bridge_priority,
            bpdu_pkt.bridge_system_id_extension,
            bpdu_pkt.bridge_mac_address)
        rcv_port_id = bpdu.ConfigurationBPDUs.encode_port_id(
            bpdu_pkt.port_priority,
            bpdu_pkt.port_number)

        if (self.port_priority is None
                or self.port_priority.value != rcv_root_id.value
                    or not equal(self.port_times, rcv_root_times)
                        or self.designated_bridge_id != rcv_bridge_id
                            or self.designated_port_id != rcv_port_id):
            update_flg = True
            # Update receive BPDU data.
            self.port_priority = rcv_root_id
            self.port_path_cost = bpdu_pkt.root_path_cost
            self.port_times = rcv_root_times
            self.designated_bridge_id = rcv_bridge_id
            self.designated_port_id = rcv_port_id
        else:
            update_flg = False  

        return update_flg, rcv_tc_flg

    def rcv_tc_bpdu(self):
        if self.state is PORT_STATE_BLOCKING:
            self._change_status(PORT_STATE_LISTENING)    
                        
    def _state_machine(self):
        while True:
            #TODO: #####################################
            state_str = {PORT_STATE_DISABLE: 'DISABLE',
                         PORT_STATE_BLOCKING: 'BLOCKING',
                         PORT_STATE_LISTENING: 'LISTENING',
                         PORT_STATE_LEARNING: 'LEARNING',
                         PORT_STATE_FORWARDING: 'FORWARDING'}
            role_str = {ROOT_PORT: 'ROOT_PORT',
                        DESIGNATED_PORT: 'DESIGNATED_PORT',
                        NON_DESIGNATED_PORT: 'NON_DESIGNATED_PORT'}
            print '[dp=%d][port=%d] %s, %s' % (self.dp.id,
                                               self.data.port_no,
                                               role_str[self.role],
                                               state_str[self.state])
            ############################################

            # Change openflow port status.
            self.ofctl.set_port_status(self.data, self.state)

            self.event = hub.Event()
            timer = self._get_timer()
            if timer:
                # Wait Timeout or self._change_status()
                timeout = hub.Timeout(timer)
                try:
                    self.event.wait()
                except hub.Timeout as t:
                    if t is not timeout:
                        raise  #TODO: not my timeout
                    self.state = self._get_next_state()
                finally:
                    timeout.cancel()
            else:
                # Wait self._change_status()
                self.event.wait()

    def _get_timer(self):
        timer = {PORT_STATE_DISABLE: None,
                 PORT_STATE_BLOCKING: self.root_times.max_age,
                 PORT_STATE_LISTENING: self.root_times.forward_delay,
                 PORT_STATE_LEARNING: self.root_times.forward_delay,
                 PORT_STATE_FORWARDING: None}
        return timer[self.state]

    def _get_next_state(self):
        next_state = {PORT_STATE_DISABLE: None,
                      PORT_STATE_BLOCKING: PORT_STATE_LISTENING,
                      PORT_STATE_LISTENING: PORT_STATE_LEARNING,
                      PORT_STATE_FORWARDING: None}
                      # PORT_STATE_LEARNING is follows.

        if self.state in next_state:
            return next_state[self.state]
        else:
            assert self.state is PORT_STATE_LEARNING
            if (self.role is ROOT_PORT
                    or self.role is DESIGNATED_PORT):
                return PORT_STATE_FORWARDING
            else:
                assert self.role is NON_DESIGNATED_PORT
                return PORT_STATE_BLOCKING

    def _change_status(self, new_state):
        """ Change status immediately (Timer is canceled) """
        self.state = new_state
        if self.event:
            self.event.set()

    def _transmit_config_bpdu(self):
        """ Send config BPDU packet if port role is DESIGNATED_PORT. """
        while True:
            if self.role == DESIGNATED_PORT:
                flags = 0b00000000
                if self.send_tc_flg:
                    flags = 0b00000001
                bpdu_data = self._generate_config_bpdu(flags)
                self.ofctl.send_packet_out(self.data.port_no, bpdu_data)
                #self.logger.info(('Send BPDU packet. [port=%d]'
                #                  % self.data.port_no,)
                #                 extra={'dpid': dpid_to_str(self.dp.id)})
            hub.sleep(self.root_times.hello_time)

    def transmit_tc_bpdu(self):
        """ Set send_tc_flg for send Topology Change BPDU. """
        timer = self.root_times.max_age + self.root_times.forward_delay

        self.send_tc_flg = True
        hub.sleep(timer)
        self.send_tc_flg = False

    def transmit_ack_bpdu(self):
        """ Send Topology Change Ack BPDU. """
        flags = 0b10000001
        bpdu_data = self._generate_config_bpdu(flags)
        self.ofctl.send_packet_out(self.data.port_no, bpdu_data)

    def transmit_tcn_bpdu(self):
        """ Send Topology Change Notification BPDU. """
        local_hello_time = bpdu.DEFAULT_HELLO_TIME
        while self.send_tcn_flg:
            bpdu_data = self._generate_tcn_bpdu()
            self.ofctl.send_packet_out(self.data.port_no, bpdu_data)
            hub.sleep(local_hello_time)

    def _generate_config_bpdu(self, flags):
        #TODO: Set system_id_extension for Vlan.
        src_mac = addrconv.mac.bin_to_text(self.data.hw_addr)
        dst_mac = addrconv.mac.bin_to_text(bpdu.BRIDGE_GROUP_ADDRESS)
        length = (bpdu.ConfigurationBPDUs.PACK_LEN
                  + llc.llc._PACK_LEN + llc.ControlFormatU._PACK_LEN)

        e = ethernet.ethernet(dst_mac, src_mac, length)
        l = llc.llc(llc.SAP_BDPU, llc.SAP_BDPU, llc.ControlFormatU())
        b = bpdu.ConfigurationBPDUs(
            flags=flags,
            root_priority=self.root_id.priority,
            root_mac_address=self.root_id.mac_addr,
            root_path_cost=self.root_path_cost,
            bridge_priority=self.bridge_id.priority,
            bridge_mac_address=self.bridge_id.mac_addr,
            port_priority=self.priority,
            port_number=self.data.port_no,
            message_age=self.root_times.message_age + 1,
            max_age=self.root_times.max_age,
            hello_time=self.root_times.hello_time,
            forward_delay=self.root_times.forward_delay)

        pkt = packet.Packet()
        pkt.add_protocol(e)
        pkt.add_protocol(l)
        pkt.add_protocol(b)
        pkt.serialize()

        return pkt.data

    def _generate_tcn_bpdu(self):
        src_mac = addrconv.mac.bin_to_text(port_id.data.hw_addr)
        dst_mac = addrconv.mac.bin_to_text(bpdu.BRIDGE_GROUP_ADDRESS)
        length = (bpdu.TopologyChangeNotificationBPDUs.PACK_LEN
                  + llc.llc._PACK_LEN + llc.ControlFormatU._PACK_LEN)

        e = ethernet.ethernet(dst_mac, src_mac, length)
        l = llc.llc(llc.SAP_BDPU, llc.SAP_BDPU, llc.ControlFormatU())
        b = bpdu.TopologyChangeNotificationBPDUs()

        pkt = packet.Packet()
        pkt.add_protocol(e)
        pkt.add_protocol(l)
        pkt.add_protocol(b)
        pkt.serialize()

        return pkt.data


class BridgeId(object):
    def __init__(self, priority, system_id_extension, mac_addr):
        super(BridgeId, self).__init__()
        self.priority = priority
        self.system_id_extension = system_id_extension
        self.mac_addr = mac_addr
        self.value = bpdu.ConfigurationBPDUs.encode_bridge_id(
            priority, system_id_extension, mac_addr)


class Times(object):
    def __init__(self, message_age, max_age, hello_time, forward_delay):
        super(Times, self).__init__()
        self.message_age = message_age
        self.max_age = max_age
        self.hello_time = hello_time
        self.forward_delay = forward_delay


class OfCtl_v1_0(object):
    def __init__(self, dp):
        super(OfCtl_v1_0, self).__init__()
        self.dp = dp

    def send_packet_out(self, out_port, data):
        actions = [self.dp.ofproto_parser.OFPActionOutput(out_port, 0)]
        self.dp.send_packet_out(buffer_id=UINT32_MAX,
                                in_port=self.dp.ofproto.OFPP_CONTROLLER,
                                actions=actions, data=data)

    def set_port_status(self, port, config):
        ofproto_parser = self.dp.ofproto_parser
        mask = 0b1111111
        msg = ofproto_parser.OFPPortMod(self.dp, port.port_no, port.hw_addr,
                                        config, mask, port.advertised)
        self.dp.send_msg(msg)
