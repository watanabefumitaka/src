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


#TODO: config comment
#TODO: port cost comment
#TODO: config Disable check
#TODO: EventPacketIn


import logging
import eventlet
import greenlet

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


STP_EV_DISPATCHER = "stp_lib"


UINT32_MAX = 0xffffffff

MAX_PORT_NO = 0xfff

# Port role
ROOT_PORT = 0
DESIGNATED_PORT = 1
NON_DESIGNATED_PORT = 2

# Port state
PORT_STATE_DISABLE = ofproto_v1_0.OFPPC_PORT_DOWN
PORT_STATE_BLOCKING = (ofproto_v1_0.OFPPC_NO_RECV
                       | ofproto_v1_0.OFPPC_NO_FLOOD
                       | ofproto_v1_0.OFPPC_NO_FWD)
PORT_STATE_LISTENING = (ofproto_v1_0.OFPPC_NO_RECV
                        | ofproto_v1_0.OFPPC_NO_FLOOD)
PORT_STATE_LEARNING = ofproto_v1_0.OFPPC_NO_FLOOD
PORT_STATE_FORWARDING = 0

# For compare config BPDU priority and times
SUPERIOR = 0
REPEATED = 1
INFERIOR = 2


# Flush filtering database, when you receive this event.
class EventTopologyChange(event.EventBase):
    def __init__(self, dp):
        super(EventTopologyChange, self).__init__()
        self.dp = dp


# Throw packet in message except BPDU packet.
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
        self.name = 'stp_lib'
        self._set_logger()
        self.config = None

    def close(self):
        [self._unregister_bridge(dpid) for dpid in self._BRIDGE_LIST.keys()]

    def _set_logger(self):
        self.logger.propagate = False
        hdlr = logging.StreamHandler()
        fmt_str = '[STP][%(levelname)s] dpid=%(dpid)s: %(message)s'
        hdlr.setFormatter(logging.Formatter(fmt_str))
        self.logger.addHandler(hdlr)

    #TODO: REST?
    def set_config(self, config):
        assert isinstance(config, dict)
        self.config = config

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [handler.MAIN_DISPATCHER, handler.DEAD_DISPATCHER])
    def dispacher_change(self, ev):
        assert ev.datapath is not None
        if ev.state == handler.MAIN_DISPATCHER:
            #TODO:
            #if ev.datapath.id != 3:
            #    self._register_bridge(ev.datapath)
            self._register_bridge(ev.datapath)
        elif ev.state == handler.DEAD_DISPATCHER:
            self._unregister_bridge(ev.datapath.id)

    def _register_bridge(self, dp):
        dpid = {'dpid': dpid_to_str(dp.id)}
        try:
            bridge = Bridge(dp, self.logger,
                            self.send_event_to_observers,
                            self.config.get(dp.id, {}))
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

    @set_ev_cls(ofp_event.EventOFPPortStatus, handler.MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        ofproto = ev.msg.datapath.ofproto
        reason = ev.msg.reason
        link_down_flg = ev.msg.desc.state & 0b1
        port_no = ev.msg.desc.port_no
        dp = ev.msg.datapath

        #TODO:
        dpid = {'dpid': dpid_to_str(dp.id)}
        stp_port_state = ev.msg.desc.state & ofproto.OFPPS_STP_MASK
        state = {ofproto.OFPPS_STP_BLOCK: 'BLOCK',
                 ofproto.OFPPS_STP_LISTEN: 'LISTEN',
                 ofproto.OFPPS_STP_LEARN: 'LEARN',
                 ofproto.OFPPS_STP_FORWARD: 'FORWARD'}
        self.logger.info('[port=%d] reason=%d, link_down_flg=%d, stp_state=%s' %
                         (ev.msg.desc.port_no, reason, link_down_flg, state[stp_port_state]),
                         extra=dpid)

        if dp.id in self._BRIDGE_LIST:
            bridge = self._BRIDGE_LIST[dp.id]

            if reason is ofproto.OFPPR_ADD:
                bridge.port_add(dp.ports[port_no])
            elif reason is ofproto.OFPPR_DELETE:
                bridge.port_delete(port_no)
            else:
                assert reason is ofproto.OFPPR_MODIFY
                if link_down_flg:
                    bridge.link_down(port_no)
                else:
                    bridge.link_up(port_no)

    @staticmethod
    def compare_root_path(path_cost1, path_cost2, bridge_id1, bridge_id2,
                          port_id1, port_id2):
        """ Compare root path by following priorities.
             [root_path_cost > designated_bridge_id > port_id] """
        if path_cost1 < path_cost2:
            return SUPERIOR
        elif path_cost1 == path_cost2:
            if bridge_id1 < bridge_id2:
                return SUPERIOR
            elif bridge_id1 == bridge_id2:
                if port_id1 < port_id2:
                    return SUPERIOR
        return INFERIOR

    @staticmethod
    def compare_priority_times(my_priority, my_times,
                               rcv_priority, rcv_times):
        """ Compare BPDU priority and times. """
        if my_priority is None:
            return SUPERIOR

        root_id = (rcv_priority.root_id.value
                   - my_priority.root_id.value)
        if root_id != 0:
            return (SUPERIOR if root_id < 0 else INFERIOR)
        path_cost = (rcv_priority.root_path_cost
                     - my_priority.root_path_cost)
        if path_cost != 0:
            return (SUPERIOR if path_cost < 0 else INFERIOR)
        d_bridge_id = (rcv_priority.designated_bridge_id
                       - my_priority.designated_bridge_id)
        if d_bridge_id != 0:
            return (SUPERIOR if d_bridge_id < 0 else INFERIOR)
        d_port_id = (rcv_priority.designated_port_id
                     - my_priority.designated_port_id)
        if d_port_id != 0:
            return (SUPERIOR if d_port_id < 0 else INFERIOR)
        #TODO:
        #((D == DesignatedBridgeID.BridgeAddress)
        #  && (PD == DesignatedPortID.PortNumber))

        # Times
        return (SUPERIOR if not equal(rcv_times, my_times)
                else REPEATED)


class Bridge(object):
    def __init__(self, dp, logger, send_ev_func, config):
        super(Bridge, self).__init__()
        self.dp = dp
        self.logger = logger
        self.dpid_str = {'dpid': dpid_to_str(dp.id)}
        self.send_event = send_ev_func

        # Bridge data
        values = {'priority': bpdu.DEFAULT_BRIDGE_PRIORITY,
                  'sys_ext_id': 0,
                  'max_age': bpdu.DEFAULT_MAX_AGE,
                  'hello_time': bpdu.DEFAULT_HELLO_TIME,
                  'fwd_delay': bpdu.DEFAULT_FORWARD_DELAY}
        bridge_conf = config.get('bridge', {})
        for key in values.keys():
            if key in bridge_conf:
                values[key] = bridge_conf[key]
        system_id = addrconv.mac.bin_to_text(dp.ports.values()[0].hw_addr)

        self.bridge_id = BridgeId(values['priority'],
                                  values['sys_ext_id'],
                                  system_id)
        self.bridge_times = Times(0,  # message_age
                                  values['max_age'],
                                  values['hello_time'],
                                  values['fwd_delay'])
        # Root bridge data
        self.root_priority = Priority(self.bridge_id, 0, None, None)
        self.root_times = self.bridge_times
        # Ports
        self.ports = {}
        self.ports_conf = config.get('ports', {})
        for port_data in dp.ports.values():
            if port_data.port_no <= MAX_PORT_NO:
                port_conf = self.ports_conf.get(port_data.port_no, {})
                self.ports[port_data.port_no] = Port(dp, logger,
                                                     send_ev_func,
                                                     self.init_spanning_tree,
                                                     port_conf,
                                                     self.bridge_id,
                                                     self.bridge_times,
                                                     port_data,
                                                     10)  #TODO: path_cost

    @property
    def is_root_bridge(self):
        return bool(self.bridge_id.value == self.root_priority.root_id.value)

    def init_spanning_tree(self):
        """ Initialize all port and become a root bridge. """
        [port.down(PORT_STATE_BLOCKING, msg_init=True)
         for port in self.ports.values()]

        self.root_priority = Priority(self.bridge_id, 0, None, None)
        self.root_times = self.bridge_times

        [port.up(DESIGNATED_PORT,
                 self.root_priority, self.root_times)
         for port in self.ports.values()]

        self.logger.info('Root bridge.', extra=self.dpid_str)

    def delete(self):
        [port.delete() for port in self.ports.values()]

    def port_add(self, port):
        #TODO:
        if port.port_no <= MAX_PORT_NO:
            port_conf = self.ports_conf.get(port.port_no, {})
            self.ports[port.port_no] = Port(self.dp, self.logger,
                                            send_ev_func,
                                            self.init_spanning_tree,
                                            port_conf,
                                            self.bridge_id,
                                            self.bridge_times,
                                            port,
                                            10)  #TODO: path_cost

    def port_delete(self, port_no):
        self.link_down(port_no)
        self.ports[port_no].delete()
        del self.ports[port_no]

    def link_up(self, port_no):
        port = self.ports[port_no]
        port.up(DESIGNATED_PORT,
                self.root_priority, self.root_times)

    def link_down(self, port_no):
        port = self.ports[port_no]

        if (port.role is DESIGNATED_PORT
                or port.role is NON_DESIGNATED_PORT):
            port.down(PORT_STATE_DISABLE, msg_init=True)

        elif port.role is ROOT_PORT:
            self.init_spanning_tree()
            #TODO: throw topology change event ?

    def packet_in_handler(self, msg):
        if not msg.in_port in self.ports:
            return

        pkt = packet.Packet(msg.data)
        in_port = self.ports[msg.in_port]

        if bpdu.ConfigurationBPDUs in pkt:
            """ Receive Configuration BPDU.
                 - Check message age.
                 - Update port receive data.
                 - If receive superior BPDU,
                    re-caluculation of spanning tree.
                    send Topology Change Notification BPDU.
                    throw EventTopologyChange.
                 - If receive Topology Change BPDU,
                    forward Topology Change BPDU.
                    throw EventTopologyChange. """
            (bpdu_pkt, ) = pkt.get_protocols(bpdu.ConfigurationBPDUs)
            if bpdu_pkt.message_age > bpdu_pkt.max_age:
                log_msg = 'Drop BPDU packet which message_age exceeded.'
                self.logger.debug(log_msg, extra=self.dpid_str)
                return

            rcv_info, rcv_tc = in_port.rcv_config_bpdu(bpdu_pkt)
            #TODO: when send EventTopologyChange ?
            #if (rcv_info is SUPERIOR
            #        or (in_port.role is ROOT_PORT and rcv_tc)):
            if rcv_info is SUPERIOR or rcv_tc:
                self.send_event(EventTopologyChange(self.dp))

            if rcv_info is SUPERIOR:
                #TODO:
                self.logger.info('[port=%d] receive superiorBPDU.', msg.in_port,
                                 extra=self.dpid_str)
                self._spanning_tree_algorithm()  # Re-caluculation of STP
                self._transmit_tcn_bpdu()

            #TODO: Root port only ?
            if in_port.role is ROOT_PORT:
                self._forward_tc_bpdu(rcv_tc)

        elif bpdu.TopologyChangeNotificationBPDUs in pkt:
            """ Receive Topology Change Notification BPDU.
                 - Throw EventTopologyChange
                 - Send Topology Change Ack BPDU.
                 - If root bridge, send Topology Change BPDU.
                   Else, send Topology Change Notification BPDU. """
            self.send_event(EventTopologyChange(self.dp))
            in_port.transmit_ack_bpdu()
            if self.is_root_bridge:
                self._transmit_tc_bpdu()
            else:
                self._transmit_tcn_bpdu()

        elif bpdu.RstBPDUs in pkt:
            """ Receive Rst BPDU. """
            #TODO:
            pass
        #TODO:
        #else:
        #    """ Receive non BPDU packet.
        #         - Throw EventPacketIn. """
        #    self.send_event(EventPacketIn(msg))

    def _spanning_tree_algorithm(self):
        """ Update tree roles.
             - Root bridge:
                all port is DesignatedPort.
             - Non root bridge:
                select one RootPort and some DesignatedPort,
                and the other port is set to NonDesignatedPort."""
        [port.down(PORT_STATE_BLOCKING, msg_init=False)
         for port in self.ports.values()]

        root_port = self._select_root_port()

        if root_port is None:
            # My bridge is a root bridge.
            self.logger.info('Root bridge.', extra=self.dpid_str)
            [port.up(DESIGNATED_PORT,
                     self.root_priority, self.root_times)
             for port in self.ports.values()
             if port.state is not PORT_STATE_DISABLE]
        else:
            # Other bridge is a root bridge.
            self.logger.info('Non root bridge.', extra=self.dpid_str)
            root_port.up(ROOT_PORT,
                         self.root_priority, self.root_times)
            selected_ports = [root_port]

            d_ports = self._select_designated_port(root_port)
            [port.up(DESIGNATED_PORT,
                     self.root_priority, self.root_times)
             for port in d_ports]
            selected_ports.extend(d_ports)

            [port.up(NON_DESIGNATED_PORT,
                     self.root_priority, self.root_times)
             for port in self.ports.values()
             if (port not in selected_ports
                     and port.state is not PORT_STATE_DISABLE)]

    def _select_root_port(self):
        self.root_priority = Priority(self.bridge_id, 0, None, None)
        self.root_times = self.bridge_times
        root_port = None

        for port in self.ports.values():
            root_msg = self.root_priority
            port_msg = port.msg_priority
            if port.state is PORT_STATE_DISABLE or port_msg is None:
                continue
            if root_msg.root_id.value > port_msg.root_id.value:
                result = SUPERIOR
            elif root_msg.root_id.value == port_msg.root_id.value:
                result = Stp.compare_root_path(port_msg.root_path_cost,
                                               root_msg.root_path_cost,
                                               port_msg.designated_bridge_id,
                                               root_msg.designated_bridge_id,
                                               port_msg.designated_port_id,
                                               root_msg.designated_port_id)
            else:
                result = INFERIOR

            if result is SUPERIOR:
                self.root_priority = port.msg_priority
                self.root_times = port.msg_times
                root_port = port

        for port in self.ports.values():
            port.port_priority = self.root_priority
            port.port_times = self.root_times

        return root_port

    def _select_designated_port(self, root_port):
        d_ports = []
        root_msg = root_port.msg_priority

        for port in self.ports.values():
            port_msg = port.msg_priority
            if (port.state is PORT_STATE_DISABLE
                    or port.data.port_no == root_port.data.port_no):
                continue
            if (port_msg is None or
                    (port_msg.root_id.value != root_msg.root_id.value)):
                d_ports.append(port)
            else:
                result = Stp.compare_root_path(root_msg.root_path_cost,
                                               (port_msg.root_path_cost
                                                - port.path_cost),
                                               self.bridge_id.value,
                                               port_msg.designated_bridge_id,
                                               port.port_id,
                                               port_msg.designated_port_id)
                if result is SUPERIOR:
                    d_ports.append(port)

        return d_ports

    def _transmit_tc_bpdu(self):
        [port.transmit_tc_bpdu() for port in self.ports.values()]

    def _transmit_tcn_bpdu(self):
        root_port = None
        for port in self.ports.values():
            if port.role is ROOT_PORT:
                root_port = port
                break
        if root_port:
            root_port.transmit_tcn_bpdu()

    def _forward_tc_bpdu(self, fwd_flg):
        for port in self.ports.values():
            port.send_tc_flg = fwd_flg


class Port(object):
    def __init__(self, dp, logger, send_ev_func, timeout_func,
                 config, bridge_id, bridge_times, data, path_cost):
        super(Port, self).__init__()
        self.dp = dp
        self.logger = logger
        self.dpid_str = {'dpid': dpid_to_str(dp.id)}
        self.send_event = send_ev_func
        self.wait_bpdu_timeout = timeout_func
        self.config = config
        self.ofctl = OfCtl_v1_0(dp)

        # Bridge data
        self.bridge_id = bridge_id

        # ofproto_v1_0_parser.OFPPhyPort data
        self.data = data
        # Port data
        values = {'priority': bpdu.DEFAULT_PORT_PRIORITY,
                  'path_cost': path_cost}
        for key in values.keys():
            if key in config:
                values[key] = config[key]
        self.priority = values['priority']
        self.path_cost = values['path_cost']
        self.port_id = bpdu.ConfigurationBPDUs.encode_port_id(self.priority,
                                                              data.port_no)
        # State and Role
        self.state = (None if config.get('enable', True)
                      else PORT_STATE_DISABLE)
        self.role = None
        # Root bridge data
        self.port_priority = None
        self.port_times = None
        # Receive BPDU data
        self.msg_priority = None
        self.msg_times = None
        # BPDU handling threads
        self.send_bpdu_thread = PortThread(self._transmit_config_bpdu)
        self.wait_bpdu_thread = PortThread(self._wait_bpdu_timer)
        self.send_tc_thread = PortThread(self._transmit_tc_bpdu)
        self.send_tcn_thread = PortThread(self._transmit_tcn_bpdu)
        self.send_tc_flg = None
        self.send_tcn_flg = None
        self.timer_event = None
        # State machine thread
        self.state_event = None
        self.state_lock = eventlet.semaphore.Semaphore()
        self.state_machine = PortThread(self._state_machine)

        self.up(DESIGNATED_PORT,
                Priority(bridge_id, 0, None, None), bridge_times)

        self.state_machine.start()
        self.logger.debug('[port=%d] Start port state machine.',
                          self.data.port_no, extra=self.dpid_str)

    def delete(self):
        self.state_lock.release()
        self.state_machine.stop()
        self.send_bpdu_thread.stop()
        self.wait_bpdu_thread.stop()
        self.send_tc_thread.stop()
        self.send_tcn_thread.stop()
        if self.state_event is not None:
            self.state_event.set()
            self.state_event = None
        if self.timer_event is not None:
            self.timer_event.set()
            self.timer_event = None
        self.logger.debug(('[port=%d] Stop port threads.'
                           % self.data.port_no), extra=self.dpid_str)

    def up(self, role, root_priority, root_times):
        self.port_priority = root_priority
        self.port_times = root_times

        self._change_role(role)
        if self.config.get('enable', True):
            self._change_status(PORT_STATE_LISTENING)
        else:
            self._change_status(PORT_STATE_DISABLE)

    def down(self, state, msg_init=False):
        assert (state is PORT_STATE_DISABLE
                    or state is PORT_STATE_BLOCKING)
        if not self.config.get('enable', True):
            return

        if msg_init:
            self.msg_priority = None
            self.msg_times = None

        self._change_role(DESIGNATED_PORT)
        self._change_status(state)

    def _state_machine(self):
        self.state_lock.acquire()

        while True:
            # for log message
            role_str = {ROOT_PORT: 'ROOT_PORT          ',
                        DESIGNATED_PORT: 'DESIGNATED_PORT    ',
                        NON_DESIGNATED_PORT: 'NON_DESIGNATED_PORT'}
            state_str = {PORT_STATE_DISABLE: 'DISABLE',
                         PORT_STATE_BLOCKING: 'BLOCKING',
                         PORT_STATE_LISTENING: 'LISTENING',
                         PORT_STATE_LEARNING: 'LEARNING',
                         PORT_STATE_FORWARDING: 'FORWARDING'}
            self.logger.info('[port=%d] %s / %s', self.data.port_no,
                             role_str[self.role], state_str[self.state],
                             extra=self.dpid_str)

            # Change openflow port status.
            self.ofctl.set_port_status(self.data, self.state)

            if (self.state is PORT_STATE_DISABLE
                    or self.state is PORT_STATE_BLOCKING):
                self.send_tc_flg = False
                self.send_tcn_flg = False
                self.send_bpdu_thread.stop()
                self.send_tc_thread.stop()
                self.send_tcn_thread.stop()
            elif self.state is PORT_STATE_LISTENING:
                self.send_bpdu_thread.start()

            # Sleep until timer is exceeded
            #  or self._change_status() is called.
            self.state_event = hub.Event()
            timer = self._get_timer()
            if timer:
                timeout = hub.Timeout(timer)
                try:
                    self.state_lock.release()
                    self.state_event.wait()
                    self.state_lock.acquire()
                except hub.Timeout as t:
                    if t is not timeout:
                        raise  #TODO: not my timeout
                    self.state_lock.acquire()
                    self.state = self._get_next_state()
                finally:
                    timeout.cancel()
            else:
                self.state_lock.release()
                self.state_event.wait()
                self.state_lock.acquire()
            
            self.state_event = None

    def _get_timer(self):
        timer = {PORT_STATE_DISABLE: None,
                 PORT_STATE_BLOCKING: None,
                 PORT_STATE_LISTENING: self.port_times.forward_delay,
                 PORT_STATE_LEARNING: self.port_times.forward_delay,
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
        self.state_lock.acquire()

        self.state = new_state
        if self.state_event is not None:
            self.state_event.set()
            self.state_event = None

        self.state_lock.release()
        hub.sleep(0)  # For thread switching.

    def _change_role(self, new_role):
        if self.role is new_role:
            return
        self.role = new_role
        if (new_role is ROOT_PORT
                or new_role is NON_DESIGNATED_PORT):
            self.wait_bpdu_thread.start()
        else:
            assert new_role is DESIGNATED_PORT
            self.wait_bpdu_thread.stop()

    def rcv_config_bpdu(self, bpdu_pkt):
        # Check TopologyChange flag.
        rcv_tc_flg = False
        tc_flag_mask = 0b00000001
        tcack_flag_mask = 0b10000000
        if bpdu_pkt.flags & tc_flag_mask:
            # receive TopologyChange message
            self.logger.debug(('[port=%d] receive TopologyChange BPDU.'
                              % self.data.port_no), extra=self.dpid_str)
            rcv_tc_flg = True
        if bpdu_pkt.flags & tcack_flag_mask:
            # receive TopologyChangeAck message
            self.logger.debug(('[port=%d] receive TopologyChangeAck BPDU.'
                              % self.data.port_no), extra=self.dpid_str)
            if self.send_tcn_flg:
                self.send_tcn_flg = False

        # Check received BPDU priority and times.
        root_id = BridgeId(bpdu_pkt.root_priority,
                           bpdu_pkt.root_system_id_extension,
                           bpdu_pkt.root_mac_address)
        root_path_cost = bpdu_pkt.root_path_cost
        designated_bridge_id = bpdu.ConfigurationBPDUs.encode_bridge_id(
            bpdu_pkt.bridge_priority,
            bpdu_pkt.bridge_system_id_extension,
            bpdu_pkt.bridge_mac_address)
        designated_port_id = bpdu.ConfigurationBPDUs.encode_port_id(
            bpdu_pkt.port_priority, bpdu_pkt.port_number)

        msg_priority = Priority(root_id, root_path_cost,
                                designated_bridge_id,
                                designated_port_id)
        msg_times = Times(bpdu_pkt.message_age,
                          bpdu_pkt.max_age,
                          bpdu_pkt.hello_time,
                          bpdu_pkt.forward_delay)

        rcv_info = Stp.compare_priority_times(self.msg_priority,
                                              self.msg_times,
                                              msg_priority,
                                              msg_times)
        if rcv_info is SUPERIOR:
            self.msg_priority = msg_priority
            self.msg_times = msg_times

        if ((rcv_info is SUPERIOR or rcv_info is REPEATED)
                and (self.role is ROOT_PORT
                        or self.role is NON_DESIGNATED_PORT)):
            self._update_wait_bpdu_timer()

        return rcv_info, rcv_tc_flg

    def _update_wait_bpdu_timer(self):
        if self.timer_event is not None:
            self.timer_event.set()
            self.timer_event = None

    def _wait_bpdu_timer(self):
        time_exceed = False
        while True:
            self.timer_event = hub.Event()
            message_age = (self.msg_times.message_age if self.msg_times
                           else 0)
            timer = self.port_times.max_age - message_age
            timeout = hub.Timeout(timer)
            try:
                self.timer_event.wait()
            except hub.Timeout as t:
                if t is not timeout:
                    raise  #TODO: not my timeout
                self.logger.info('[port=%d] Wait BPDU timer is exceeded.'
                                 % self.data.port_no, extra=self.dpid_str)
                time_exceed = True
            finally:
                timeout.cancel()

            if time_exceed:
                break

        if time_exceed:
            hub.spawn(self.wait_bpdu_timeout)  # Bridge.init_spanning_tree()
            #TODO: throw topology change event ?

    def _transmit_config_bpdu(self):
        """ Send config BPDU packet if port role is DESIGNATED_PORT. """
        while True:
            if self.role == DESIGNATED_PORT:
                flags = 0b00000000
                log_msg = '[port=%d] Send Config BPDU.'
                if self.send_tc_flg:
                    flags = 0b00000001
                    log_msg = '[port=%d] Send TopologyChange BPDU.'
                bpdu_data = self._generate_config_bpdu(flags)
                self.ofctl.send_packet_out(self.data.port_no, bpdu_data)
                self.logger.debug(log_msg % self.data.port_no,
                                  extra=self.dpid_str)
            hub.sleep(self.port_times.hello_time)

    def transmit_tc_bpdu(self):
        self.send_tc_thread.start()

    def _transmit_tc_bpdu(self):
        """ Set send_tc_flg to send Topology Change BPDU. """
        timer = self.port_times.max_age + self.port_times.forward_delay

        self.send_tc_flg = True
        hub.sleep(timer)
        self.send_tc_flg = False

    def transmit_ack_bpdu(self):
        """ Send Topology Change Ack BPDU. """
        ack_flags = 0b10000001
        bpdu_data = self._generate_config_bpdu(ack_flags)
        self.ofctl.send_packet_out(self.data.port_no, bpdu_data)

    def transmit_tcn_bpdu(self):
        self.send_tcn_thread.start()

    def _transmit_tcn_bpdu(self):
        """ Send Topology Change Notification BPDU. """
        self.send_tcn_flg = True
        local_hello_time = bpdu.DEFAULT_HELLO_TIME
        while self.send_tcn_flg:
            bpdu_data = self._generate_tcn_bpdu()
            self.ofctl.send_packet_out(self.data.port_no, bpdu_data)
            self.logger.debug(('[port=%d] Send TopologyChangeNotify BPDU.'
                               % self.data.port_no), extra=self.dpid_str)
            hub.sleep(local_hello_time)

    def _generate_config_bpdu(self, flags):
        src_mac = addrconv.mac.bin_to_text(self.data.hw_addr)
        dst_mac = addrconv.mac.bin_to_text(bpdu.BRIDGE_GROUP_ADDRESS)
        length = (bpdu.bpdu._PACK_LEN + bpdu.ConfigurationBPDUs.PACK_LEN
                  + llc.llc._PACK_LEN + llc.ControlFormatU._PACK_LEN)

        e = ethernet.ethernet(dst_mac, src_mac, length)
        l = llc.llc(llc.SAP_BDPU, llc.SAP_BDPU, llc.ControlFormatU())
        b = bpdu.ConfigurationBPDUs(
            flags=flags,
            root_priority=self.port_priority.root_id.priority,
            root_mac_address=self.port_priority.root_id.mac_addr,
            root_path_cost=self.port_priority.root_path_cost+self.path_cost,
            bridge_priority=self.bridge_id.priority,
            bridge_mac_address=self.bridge_id.mac_addr,
            port_priority=self.priority,
            port_number=self.data.port_no,
            message_age=self.port_times.message_age + 1,
            max_age=self.port_times.max_age,
            hello_time=self.port_times.hello_time,
            forward_delay=self.port_times.forward_delay)

        pkt = packet.Packet()
        pkt.add_protocol(e)
        pkt.add_protocol(l)
        pkt.add_protocol(b)
        pkt.serialize()

        return pkt.data

    def _generate_tcn_bpdu(self):
        src_mac = addrconv.mac.bin_to_text(self.data.hw_addr)
        dst_mac = addrconv.mac.bin_to_text(bpdu.BRIDGE_GROUP_ADDRESS)
        length = (bpdu.bpdu._PACK_LEN
                  + bpdu.TopologyChangeNotificationBPDUs.PACK_LEN
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


class PortThread(object):
    def __init__(self, function):
        super(PortThread, self).__init__()
        self.function = function
        self.thread = None

    def start(self):
        if self.thread is None:
            self.thread = hub.spawn(self.function)

    def stop(self):
        if self.thread is not None:
            hub.kill(self.thread)
            try:
                self.thread.wait()
            except greenlet.GreenletExit:
                pass
            self.thread = None


class BridgeId(object):
    def __init__(self, priority, system_id_extension, mac_addr):
        super(BridgeId, self).__init__()
        self.priority = priority
        self.system_id_extension = system_id_extension
        self.mac_addr = mac_addr
        self.value = bpdu.ConfigurationBPDUs.encode_bridge_id(
            priority, system_id_extension, mac_addr)


class Priority(object):
    def __init__(self, root_id, root_path_cost,
                 designated_bridge_id, designated_port_id):
        super(Priority, self).__init__()
        self.root_id = root_id
        self.root_path_cost = root_path_cost
        self.designated_bridge_id = designated_bridge_id
        self.designated_port_id = designated_port_id


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
