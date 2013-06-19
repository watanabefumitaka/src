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
import socket
import struct

import json
from webob import Response

from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import WSGIApplication
from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.exception import OFPUnknownVersion
from ryu.exception import RyuException
from ryu.lib import dpid as dpid_lib
from ryu.lib import hub
from ryu.lib import mac as mac_lib
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import vlan
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_2_parser


LOG = logging.getLogger('ryu.app.rest_router')


MSGLIST = ['=============================',
           '          REST API',
           '=============================',
           '',
           '  Note: specify switch and vlan group, as follows.',
           '   {switch_id} : "all" or switchID',
           '   {vlan_id}   : "all" or vlanID',
           '',
           '',
           ' 1. get address data and routing data.',
           '',
           ' * get data of no vlan',
           ' GET /router/{switch_id}',
           '',
           ' * get data of specific vlan group',
           ' GET /router/{switch_id}/{vlan_id}',
           '',
           '',
           ' 2. set address data or routing data.',
           '',
           ' * set data of no vlan',
           ' POST /router/{switch_id}',
           '',
           ' * set data of specific vlan group',
           ' POST /router/{switch_id}/{vlan_id}',
           '',
           '  case1: set address data.',
           '   parameter = {"address": "A.B.C.D/M"}',
           '  case2-1: set static route.',
           '   parameter = {"destination": "A.B.C.D/M", "gateway": "E.F.G.H"}',
           '  case2-2: set default route.',
           '   parameter = {"gateway": "E.F.G.H"}',
           '',
           '',
           ' 3. delete address data or routing data.',
           '',
           ' * delete data of no vlan',
           ' DELETE /router/{switch_id}',
           '',
           ' * delete data of specific vlan group',
           ' DELETE /router/{switch_id}/{vlan_id}',
           '',
           '  case1: delete address data.',
           '   parameter = {"address_id": "<int>"} or {"address_id": "all"}',
           '  case2: delete routing data.',
           '   parameter = {"route_id": "<int>"} or {"route_id": "all"}']


ETHERNET = ethernet.ethernet.__name__
VLAN = vlan.vlan.__name__
IPV4 = ipv4.ipv4.__name__
ARP = arp.arp.__name__
ICMP = icmp.icmp.__name__
TCP = tcp.tcp.__name__
UDP = udp.udp.__name__

MAX_SUSPENDPACKETS = 50  # threshold of the packet suspend threads count.

ARP_REPLY_TIMER = 2  # sec
OFP_REPLY_TIMER = 1.0  # sec
CHK_ROUTING_TBL_INTERVAL = 600  # sec

SWITCHID_PATTERN = dpid_lib.DPID_PATTERN + r'|all'
VLANID_PATTERN = r'[0-9]{1,4}|all'

VLANID_NONE = 0
VLANID_MIN = 2
VLANID_MAX = 4094

COOKIE_SHIFT_VLANID = 32
COOKIE_SHIFT_ROUTEID = 16

NETMASK_MAX = 32

PRIORITY_VLAN_SHIFT = 1000
PRIORITY_NORMAL = 0
PRIORITY_ARP_HANDLING = 1
PRIORITY_DEFAULT_ROUTING = 1
PRIORITY_MAC_LEARNING = 2
PRIORITY_STATIC_ROUTING = 2
PRIORITY_IMPLICIT_ROUTING = 3 + NETMASK_MAX
PRIORITY_L2_SWITCHING = 4 + NETMASK_MAX
PRIORITY_IP_HANDLING = 5 + NETMASK_MAX

DEFAULT_ROUTE = '0.0.0.0/0'
IDLE_TIMEOUT = 1800  # sec
DEFAULT_TTL = 64

REST_USAGE = 'usage'
REST_COMMAND_RESULT = 'command_result'
REST_RESULT = 'result'
REST_DETAILS = 'details'
REST_OK = 'success'
REST_NG = 'failure'
REST_ALL = 'all'
REST_SWITCHID = 'switch_id'
REST_VLANID = 'vlan_id'
REST_NW = 'internal_network'
REST_ADDRESSID = 'address_id'
REST_ADDRESS = 'address'
REST_ROUTEID = 'route_id'
REST_ROUTE = 'route'
REST_DESTINATION = 'destination'
REST_GATEWAY = 'gateway'


def log_info(switch_id, massage):
    sw_id = 'switch_id=%s' % dpid_lib.dpid_to_str(switch_id)
    msg = '[RT][INFO] %s: %s' % (sw_id, massage)
    LOG.info(msg)


def log_debug(switch_id, massage):
    sw_id = 'switch_id=%s' % dpid_lib.dpid_to_str(switch_id)
    msg = '[RT][DEBUG] %s: %s' % (sw_id, massage)
    LOG.debug(msg)


class NotFoundError(RyuException):
    message = 'router sw is not connected. : switch_id=%(switch_id)s'


class CommandFailure(RyuException):
    pass


class RestRouterAPI(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
                    ofproto_v1_2.OFP_VERSION]

    _CONTEXTS = {'dpset': dpset.DPSet,
                 'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(RestRouterAPI, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {}
        self.data['waiters'] = self.waiters

        mapper = wsgi.mapper
        wsgi.registory['RouterController'] = self.data
        requirements = {'switch_id': SWITCHID_PATTERN,
                        'vlan_id': VLANID_PATTERN}

        # for no VLAN data
        path = '/router/{switch_id}'
        mapper.connect('router', path, controller=RouterController,
                       requirements=requirements,
                       action='get_data',
                       conditions=dict(method=['GET']))
        mapper.connect('router', path, controller=RouterController,
                       requirements=requirements,
                       action='set_data',
                       conditions=dict(method=['POST']))
        mapper.connect('router', path, controller=RouterController,
                       requirements=requirements,
                       action='delete_data',
                       conditions=dict(method=['DELETE']))
        # for VLAN data
        path = '/router/{switch_id}/{vlan_id}'
        mapper.connect('router', path, controller=RouterController,
                       requirements=requirements,
                       action='get_vlan_data',
                       conditions=dict(method=['GET']))
        mapper.connect('router', path, controller=RouterController,
                       requirements=requirements,
                       action='set_vlan_data',
                       conditions=dict(method=['POST']))
        mapper.connect('router', path, controller=RouterController,
                       requirements=requirements,
                       action='delete_vlan_data',
                       conditions=dict(method=['DELETE']))

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
        if ev.enter:
            RouterController.regist_router(ev.dp)
        else:
            RouterController.unregist_router(ev.dp)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        RouterController.packet_in_handler(ev.msg)

    def stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if (dp.id not in self.waiters
                or msg.xid not in self.waiters[dp.id]):
            return
        event, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)

        if msg.flags & dp.ofproto.OFPSF_REPLY_MORE:
            return
        del self.waiters[dp.id][msg.xid]
        event.set()

    # for OpenFlow version1.0
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_0(self, ev):
        self.stats_reply_handler(ev)

    # for OpenFlow version1.2
    @set_ev_cls(ofp_event.EventOFPStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_2(self, ev):
        self.stats_reply_handler(ev)

    #TODO: Update Routing table when Port status is changed.


# REST command template
def rest_command(func):
    def _rest_command(*args, **kwargs):
        try:
            msg = func(*args, **kwargs)
            return Response(content_type='application/json',
                            body=json.dumps(msg))

        except (SyntaxError, ValueError, NameError) as e:
            status = 400
            details = e.message

        except KeyError, key:
            status = 400
            details = 'Required [%s] parameter.' % key

        except NotFoundError, msg:
            status = 404
            details = str(msg)

        msg = {REST_RESULT: REST_NG,
               REST_DETAILS: details,
               REST_USAGE: MSGLIST}
        return Response(status=status, body=json.dumps(msg))

    return _rest_command


class RouterController(ControllerBase):

    _ROUTER_LIST = {}

    def __init__(self, req, link, data, **config):
        super(RouterController, self).__init__(req, link, data, **config)
        self.waiters = data['waiters']

    @staticmethod
    def regist_router(dp):
        try:
            router = Router(dp)
        except OFPUnknownVersion, message:
            LOG.error('dpid=%s : %s' %
                      (dpid_lib.dpid_to_str(dp.id), message))
            return
        RouterController._ROUTER_LIST.setdefault(dp.id, router)
        log_info(dp.id, 'Join as router.')

    @staticmethod
    def unregist_router(dp):
        if dp.id in RouterController._ROUTER_LIST:
            RouterController._ROUTER_LIST[dp.id].delete()
            del RouterController._ROUTER_LIST[dp.id]
            log_info(dp.id, 'Leave router.')

    def _get_router(self, switch_id):
        routers = {}

        if switch_id == REST_ALL:
            routers = self._ROUTER_LIST
        else:
            sw_id = dpid_lib.str_to_dpid(switch_id)
            if sw_id in self._ROUTER_LIST:
                routers = {sw_id: self._ROUTER_LIST[sw_id]}

        if routers:
            return routers
        else:
            raise NotFoundError(switch_id=switch_id)

    @staticmethod
    def packet_in_handler(msg):
        dp_id = msg.datapath.id

        pkt = packet.Packet(msg.data)
        log_msg = 'PacketIn = %s' % str(pkt)
        log_info(dp_id, log_msg)
        header_list = dict((p.protocol_name, p)
                           for p in pkt.protocols if type(p) != str)
        if header_list:
            if dp_id in RouterController._ROUTER_LIST:
                router = RouterController._ROUTER_LIST[dp_id]
                router.event_handler(msg, header_list)
            else:
                switch_id = dpid_lib.dpid_to_str(dp_id)
                raise NotFoundError(switch_id=switch_id)

    # GET /router/{switch_id}
    @rest_command
    def get_data(self, dummy, switch_id, **_kwargs):
        return self._access_router(switch_id, VLANID_NONE, 'get_data')

    # GET /router/{switch_id}/{vlan_id}
    @rest_command
    def get_vlan_data(self, dummy, switch_id, vlan_id, **_kwargs):
        return self._access_router(switch_id, vlan_id, 'get_data')

    # POST /router/{switch_id}
    @rest_command
    def set_data(self, req, switch_id, **_kwargs):
        set_data = eval(req.body)
        return self._access_router(switch_id, VLANID_NONE,
                                   'set_data', param=set_data)

    # POST /router/{switch_id}/{vlan_id}
    @rest_command
    def set_vlan_data(self, req, switch_id, vlan_id, **_kwargs):
        set_data = eval(req.body)
        return self._access_router(switch_id, vlan_id,
                                   'set_data', param=set_data)

    # DELETE /router/{switch_id}
    @rest_command
    def delete_data(self, req, switch_id, **_kwargs):
        delete_data = eval(req.body)
        return self._access_router(switch_id, VLANID_NONE,
                                   'delete_data', param=delete_data)

    # DELETE /router/{switch_id}/{vlan_id}
    @rest_command
    def delete_vlan_data(self, req, switch_id, vlan_id, **_kwargs):
        delete_data = eval(req.body)
        return self._access_router(switch_id, vlan_id,
                                   'delete_data', param=delete_data)

    def _access_router(self, switch_id, vlan_id, func, param=None):
        rest_message = []
        routers = self._get_router(switch_id)
        for router in routers.values():
            function = getattr(router, func)
            data = function(vlan_id, param, self.waiters)
            rest_message.append(data)

        return rest_message


class Router(dict):
    def __init__(self, dp):
        super(Router, self).__init__()
        self.dp = dp
        self.sw_id = dpid_lib.dpid_to_str(dp.id)
        self.port_data = PortData(dp.ports)

        ofctl = OfCtl.factory(dp)
        cookie = 0

        # set SW config: TTL error PacketIn(only OFPv1.2)
        ofctl.set_sw_config_for_ttl()

        # set Flow: ARP handling(PacketIn)
        self.ofctl.set_packetin_flow(cookie, PRIORITY_ARP_HANDLING,
                                     dl_type=ether.ETH_TYPE_ARP)
        log_info(dp.id,
                 'Set ARPhandling(PacketIn) Flow [cookie=0x%x]' % cookie)

        # set Flow: IP handling(PacketIn)
        for port in self.port_data.values():
            self.ofctl.set_packetin_flow(cookie,
                                         PRIORITY_IP_HANDLING,
                                         dl_type=ether.ETH_TYPE_IP,
                                         dl_dst=port.mac)
        log_info(dp.id,
                 'Set IPhandling(PacketIn) Flow [cookie=0x%x]' % cookie)

        # set Flow: L2 switching(NORMAL)
        ofctl.set_normal_flow(cookie, PRIORITY_NORMAL)
        log_info(dp.id, 'Set L2switching(NORMAL) Flow [cookie=0x%x]' % cookie)

        # set VlanRouter for vid=None.
        vlan_router = VlanRouter(VLANID_NONE, dp, self.port_data)
        self.setdefault(VLANID_NONE, vlan_router)

        # start cyclic Routing table check.
        self.is_active = True
        hub.spawn(self._cyclic_update_routing_tbl)

    def delete(self):
        self.is_active = False

    def _get_vlan_router(self, vlan_id):
        vlan_routers = []

        if vlan_id == REST_ALL:
            vlan_routers = self.values()
        else:
            vlan_id = int(vlan_id)
            if (vlan_id != VLANID_NONE and
                    (vlan_id < VLANID_MIN or VLANID_MAX < vlan_id)):
                msg = 'Invalid {vlan_id} value. Set [%d-%d]' % (VLANID_MIN,
                                                                VLANID_MAX)
                raise ValueError(msg)
            elif vlan_id in self:
                vlan_routers = [self[vlan_id]]

        return vlan_routers

    def _add_vlan_router(self, vlan_id):
        vlan_id = int(vlan_id)
        if vlan_id not in self:
            vlan_router = VlanRouter(vlan_id, self.dp, self.port_data)
            self.setdefault(vlan_id, vlan_router)
        return self[vlan_id]

    def _del_vlan_router(self, vlan_id, waiters):
        #  Remove unnecessary VlanRouter.
        if vlan_id == VLANID_NONE:
            return

        vlan_router = self[vlan_id]
        if (len(vlan_router.address_data) == 0
                and len(vlan_router.routing_tbl) == 0):
            vlan_router.delete(waiters)
            del self[vlan_id]

    def get_data(self, vlan_id, dummy1, dummy2):
        msgs = []
        vlan_routers = self._get_vlan_router(vlan_id)
        if vlan_routers:
            for vlan_router in vlan_routers:
                msg = vlan_router.get_data()
                if msg:
                    msgs.append(msg)
        else:
            msgs = [{REST_VLANID: vlan_id}]

        return {REST_SWITCHID: self.sw_id,
                REST_NW: msgs}

    def set_data(self, vlan_id, data, waiters):
        vlan_routers = self._get_vlan_router(vlan_id)
        if not vlan_routers:
            vlan_routers = [self._add_vlan_router(vlan_id)]

        msgs = []
        for vlan_router in vlan_routers:
            try:
                msg = vlan_router.set_data(data)
                msgs.append(msg)
                if msg[REST_RESULT] == REST_NG:
                    # data setting is failure
                    self._del_vlan_router(vlan_router.vlan_id, waiters)
            except Exception as err_msg:
                # data setting is failure
                self._del_vlan_router(vlan_router.vlan_id, waiters)
                raise err_msg

        return {REST_SWITCHID: self.sw_id,
                REST_COMMAND_RESULT: msgs}

    def delete_data(self, vlan_id, data, waiters):
        msgs = []
        vlan_routers = self._get_vlan_router(vlan_id)
        if vlan_routers:
            for vlan_router in vlan_routers:
                msg = vlan_router.delete_data(data, waiters)
                if msg:
                    msgs.append(msg)
                # check unnecessary VlanRouter.
                self._del_vlan_router(vlan_router.vlan_id, waiters)
        if not msgs:
            msgs = [{REST_RESULT: REST_NG,
                     REST_DETAILS: 'Data is nothing.'}]

        return {REST_SWITCHID: self.sw_id,
                REST_COMMAND_RESULT: msgs}

    def event_handler(self, msg, header_list):
        ofproto = self.dp.ofproto

        # Check VLAN-tag
        vlan_id = VLANID_NONE
        if VLAN in header_list:
            vlan_id = header_list[VLAN].vid
        if vlan_id not in self:
            log_debug(self.dp.id,
                      'Drop unknown VLAN packet. [vlan_id=%d]' % vlan_id)
            return

        # Check invalid TTL (only OpenFlow V1.2)
        if ofproto.OFP_VERSION == ofproto_v1_2.OFP_VERSION:
            if msg.reason == ofproto.OFPR_INVALID_TTL:
                self[vlan_id].event_invalid_ttl(msg, header_list)
                return

        # Analyze event type.
        if ARP in header_list:
            self[vlan_id].event_arp(msg, header_list)
            return

        if IPV4 in header_list:
            default_routes = self[vlan_id].address_data.get_default_routes()
            if header_list[IPV4].dst in default_routes:
                # Packet to Router's port.
                if ICMP in header_list:
                    if header_list[ICMP].type == icmp.ICMP_ECHO_REQUEST:
                        self[vlan_id].event_icmp_req(msg, header_list)
                        return
                elif TCP in header_list or UDP in header_list:
                    self[vlan_id].event_tcp_udp(msg, header_list)
                    return
            else:
                # Packet to internal host or gateway Router.
                self[vlan_id].event_packetin_node(msg, header_list)
                return

    def _cyclic_update_routing_tbl(self):
        log_info(self.dp.id, 'Start cyclic Routing table update.')
        while self.is_active:
            # send ARP to all gateways.
            for vlan_router in self.values():
                vlan_router.send_arp_all_gw()
                hub.sleep(1)

            hub.sleep(CHK_ROUTING_TBL_INTERVAL)
        log_info(self.dp.id, 'Stop cyclic Routing table update.')


class VlanRouter(object):
    def __init__(self, vlan_id, dp, port_data):
        super(VlanRouter, self).__init__()
        self.vlan_id = vlan_id
        self.dp = dp

        self.port_data = port_data
        self.address_data = AddressData()
        self.routing_tbl = RoutingTable()
        self.packet_buffer = SuspendPacketList(self.send_icmp_unreach_error)
        self.ofctl = OfCtl.factory(dp)

        # set Flow: DefaultRoute(drop)
        self._set_defaultroute_drop()

    def delete(self, waiters):
        # Get all Flow.
        msgs = self.ofctl.get_all_flow(waiters)
        for msg in msgs:
            for stats in msg.body:
                vlan_id = self._cookie_to_id(REST_VLANID, stats.cookie)
                if vlan_id == self.vlan_id:
                    # Delete Flow.
                    self.ofctl.delete_flow(stats)

    def _cookie_to_id(self, id_type, cookie):
        uint32max = ofproto_v1_2_parser.UINT32_MAX

        if id_type == REST_VLANID:
            rest_id = cookie >> COOKIE_SHIFT_VLANID
        elif id_type == REST_ADDRESSID:
            rest_id = cookie & uint32max
        else:
            assert id_type == REST_ROUTEID
            rest_id = (cookie & uint32max) >> COOKIE_SHIFT_ROUTEID

        return rest_id

    def _id_to_cookie(self, id_type, rest_id):
        vid = self.vlan_id << COOKIE_SHIFT_VLANID

        if id_type == REST_VLANID:
            cookie = rest_id << COOKIE_SHIFT_VLANID
        elif id_type == REST_ADDRESSID:
            cookie = vid + rest_id
        else:
            assert id_type == REST_ROUTEID
            cookie = vid + (rest_id << COOKIE_SHIFT_ROUTEID)

        return cookie

    def _response(self, msg):
        if msg and self.vlan_id:
            msg.setdefault(REST_VLANID, self.vlan_id)
        return msg

    def get_data(self):
        address_data = self._get_address_data()
        routing_data = self._get_routing_data()

        data = {}
        if address_data[REST_ADDRESS]:
            data.update(address_data)
        if routing_data[REST_ROUTE]:
            data.update(routing_data)

        return self._response(data)

    def _get_address_data(self):
        address_data = []
        for value in self.address_data.values():
            default_route = ip_addr_ntoa(value.default_route)
            address = '%s/%d' % (default_route, value.netmask)
            data = {REST_ADDRESSID: value.address_id,
                    REST_ADDRESS: address}
            address_data.append(data)
        return {REST_ADDRESS: address_data}

    def _get_routing_data(self):
        routing_data = []
        for key, value in self.routing_tbl.items():
            if value.gateway_mac is not None:
                gateway = ip_addr_ntoa(value.gateway_ip)
                data = {REST_ROUTEID: value.route_id,
                        REST_DESTINATION: key,
                        REST_GATEWAY: gateway}
                routing_data.append(data)
        return {REST_ROUTE: routing_data}

    def set_data(self, data):
        details = None

        try:
            # set Address data
            if REST_ADDRESS in data:
                address = data[REST_ADDRESS]
                address_id = self._set_address_data(address)
                details = 'add Address [address_id=%d]' % address_id
            # set Routing data
            elif REST_GATEWAY in data:
                gateway = data[REST_GATEWAY]
                if REST_DESTINATION in data:
                    destination = data[REST_DESTINATION]
                else:
                    destination = DEFAULT_ROUTE
                route_id = self._set_routing_data(destination, gateway)
                details = 'add Route [route_id=%d]' % route_id

        except CommandFailure as err_msg:
            msg = {REST_RESULT: REST_NG, REST_DETAILS: str(err_msg)}
            return self._response(msg)

        if details is not None:
            msg = {REST_RESULT: REST_OK, REST_DETAILS: details}
            return self._response(msg)
        else:
            raise ValueError('Invalid parameter.')

    def _set_address_data(self, address):
        address = self.address_data.add(address)

        cookie = self._id_to_cookie(REST_ADDRESSID, address.address_id)

        # set Flow: Host MAC learning(PacketIn)
        self.ofctl.set_packetin_flow(cookie,
                                     PRIORITY_MAC_LEARNING,
                                     dl_type=ether.ETH_TYPE_IP,
                                     dl_vlan=self.vlan_id,
                                     dst_ip=address.nw_addr,
                                     dst_mask=address.netmask)
        log_info(self.dp.id,
                 'Set HostMAClearning(PacketIn) Flow [cookie=0x%x]' % cookie)

        # set Flow: L2 switching(NORMAL)
        outport = self.ofctl.dp.ofproto.OFPP_NORMAL
        self.ofctl.set_routing_flow(
            cookie, PRIORITY_L2_SWITCHING, outport, dl_vlan=self.vlan_id,
            nw_src=address.nw_addr, src_mask=address.netmask,
            nw_dst=address.nw_addr, dst_mask=address.netmask)
        log_info(self.dp.id,
                 'Set L2switching(NORMAL) Flow [cookie=0x%x]' % cookie)

        # send GARP
        self.send_arp_request(address.default_route, address.default_route)

        return address.address_id

    def _set_routing_data(self, destination, gateway):
        try:
            dst_ip = ip_addr_aton(gateway)
        except ValueError:
            msg = 'Invalid [%s] value.' % REST_GATEWAY
            raise ValueError(msg)
        address = self.address_data.get_data(dst_ip)
        if address is None:
            msg = 'Gateway=%s\'s Address is not registered.' % gateway
            raise CommandFailure(msg=msg)
        elif dst_ip == address.default_route:
            msg = 'Gateway=%s is used as DefaultRoute of address_id=%d'\
                % (gateway, address.address_id)
            raise CommandFailure(msg=msg)
        else:
            src_ip = address.default_route
            route = self.routing_tbl.add(destination, gateway)
            self._set_route_packetin(route)
            self.send_arp_request(src_ip, dst_ip)
            return route.route_id

    def _set_defaultroute_drop(self):
        cookie = self._id_to_cookie(REST_VLANID, self.vlan_id)
        outport = None  # for drop
        self.ofctl.set_routing_flow(cookie, PRIORITY_DEFAULT_ROUTING,
                                    outport, dl_vlan=self.vlan_id)
        log_info(self.dp.id,
                 'Set DefaultRouting(drop) Flow [cookie=0x%x]' % cookie)

    def _set_route_packetin(self, route):
        cookie = self._id_to_cookie(REST_ROUTEID, route.route_id)
        if route.dst_ip:
            priority = PRIORITY_STATIC_ROUTING + route.netmask
            log_msg = 'StaticRouting'
        else:
            priority = PRIORITY_DEFAULT_ROUTING
            log_msg = 'DefaultRouting'
        self.ofctl.set_packetin_flow(cookie, priority,
                                     dl_type=ether.ETH_TYPE_IP,
                                     dl_vlan=self.vlan_id,
                                     dst_ip=route.dst_ip,
                                     dst_mask=route.netmask)
        log_info(self.dp.id,
                 'Set %s(PacketIn) Flow [cookie=0x%x]' % (log_msg, cookie))

    def delete_data(self, data, waiters):
        if REST_ROUTEID in data:
            route_id = data[REST_ROUTEID]
            msg = self._delete_routing_data(route_id, waiters)
        elif REST_ADDRESSID in data:
            address_id = data[REST_ADDRESSID]
            msg = self._delete_address_data(address_id, waiters)
        else:
            raise ValueError('Invalid parameter.')

        return self._response(msg)

    def _delete_address_data(self, address_id, waiters):
        if address_id != REST_ALL:
            try:
                address_id = int(address_id)
            except ValueError:
                raise ValueError('Invalid [%s] value.' % REST_ADDRESSID)

        skip_ids = self._chk_addr_relation_route(address_id)

        # Get all Flow.
        delete_list = []
        msgs = self.ofctl.get_all_flow(waiters)
        max_id = ofproto_v1_2_parser.UINT16_MAX
        for msg in msgs:
            for stats in msg.body:
                vlan_id = self._cookie_to_id(REST_VLANID, stats.cookie)
                if vlan_id != self.vlan_id:
                    continue
                addr_id = self._cookie_to_id(REST_ADDRESSID, stats.cookie)
                if addr_id in skip_ids:
                    continue
                elif address_id == REST_ALL:
                    if addr_id <= 0 or max_id < addr_id:
                        continue
                elif address_id != addr_id:
                    continue
                delete_list.append(stats)

        # Delete Flow
        delete_ids = []
        for flow_stats in delete_list:
            self.ofctl.delete_flow(flow_stats)
            address_id = self._cookie_to_id(REST_ADDRESSID, flow_stats.cookie)
            self.address_data.delete(address_id)
            if address_id not in delete_ids:
                delete_ids.append(address_id)

        msg = {}
        if delete_ids:
            address_id = ''
            for addressid in delete_ids:
                if address_id != '':
                    address_id += ','
                address_id += str(addressid)
            details = 'delete Address [address_id=%s]' % address_id
            msg = {REST_RESULT: REST_OK, REST_DETAILS: details}

        if skip_ids:
            address_id = ''
            for addressid in skip_ids:
                if address_id != '':
                    address_id += ','
                address_id += str(addressid)
            details = 'skip delete(related Route exist) [address_id=%s]'\
                % address_id
            if msg:
                msg[REST_DETAILS] += ', %s' % details
            else:
                msg = {REST_RESULT: REST_NG, REST_DETAILS: details}

        return msg

    def _delete_routing_data(self, route_id, waiters):
        if route_id != REST_ALL:
            try:
                route_id = int(route_id)
            except ValueError:
                raise ValueError('Invalid [%s] value.' % REST_ROUTEID)

        # Get all Flow.
        msgs = self.ofctl.get_all_flow(waiters)

        delete_list = []
        for msg in msgs:
            for stats in msg.body:
                vlan_id = self._cookie_to_id(REST_VLANID, stats.cookie)
                if vlan_id != self.vlan_id:
                    continue
                rt_id = self._cookie_to_id(REST_ROUTEID, stats.cookie)
                if route_id == REST_ALL:
                    if rt_id == 0:
                        continue
                elif route_id != rt_id:
                    continue
                delete_list.append(stats)

        # Delete Flow.
        delete_ids = []
        for flow_stats in delete_list:
            self.ofctl.delete_flow(flow_stats)
            route_id = self._cookie_to_id(REST_ROUTEID, flow_stats.cookie)
            self.routing_tbl.delete(route_id)
            if route_id not in delete_ids:
                delete_ids.append(route_id)

            # case DefaultRoute deleted. -> set Flow(drop)
            priority = flow_stats.priority
            if self.vlan_id:
                priority -= PRIORITY_VLAN_SHIFT
            if priority == PRIORITY_DEFAULT_ROUTING:
                self._set_defaultroute_drop()

        msg = {}
        if delete_ids:
            route_id = ''
            for routeid in delete_ids:
                if route_id != '':
                    route_id += ','
                route_id += str(routeid)
            details = 'delete Route [route_id=%s]' % route_id
            msg = {REST_RESULT: REST_OK, REST_DETAILS: details}

        return msg

    def _chk_addr_relation_route(self, address_id):
        # Check exist of related routing data.
        relate_list = []
        gateways = self.routing_tbl.get_gateways()
        for gateway in gateways:
            address = self.address_data.get_data(gateway)
            if address is not None:
                if address_id == REST_ALL:
                    relate_list.append(address.address_id)
                elif address.address_id == address_id:
                    relate_list = [address_id]
                    break
        return relate_list

    def event_arp(self, msg, header_list):
        src_addr = self.address_data.get_data(header_list[ARP].src_ip)
        if src_addr is None:
            return

        # case: receive ARP from Gateway
        #  Update routing table.
        # case: receive ARP from internal Host
        #  Learning host MAC.
        gw_flg = self._update_routing_tbl(msg, header_list)
        if gw_flg is False:
            self._learning_host_mac(msg, header_list)

        vlan_id = VLANID_NONE
        if VLAN in header_list:
            vlan_id = header_list[VLAN].vid
        if vlan_id != self.vlan_id:
            return

        # ARP packet handling.
        default_routes = self.address_data.get_default_routes()
        in_port = self.ofctl.get_packetin_inport(msg)

        if header_list[ARP].src_ip == header_list[ARP].dst_ip:
            # GARP -> packet forward(NORMAL)
            log_debug(self.dp.id, 'receive GARP.')
            output = self.ofctl.dp.ofproto.OFPP_NORMAL
            self.ofctl.send_packet_out(in_port, output, msg.data)

        elif header_list[ARP].dst_ip not in default_routes:
            dst_addr = self.address_data.get_data(header_list[ARP].dst_ip)
            if (dst_addr is not None and
                    src_addr.address_id == dst_addr.address_id):
                # ARP from internal Host -> packet forward(NORMAL)
                log_debug(self.dp.id, 'receive ARP from internal Host.')
                output = self.ofctl.dp.ofproto.OFPP_NORMAL
                self.ofctl.send_packet_out(in_port, output, msg.data)
        else:
            if header_list[ARP].opcode == arp.ARP_REQUEST:
                # ARPrequest to Router Port -> send ARP reply
                log_debug(self.dp.id, 'receive ARPrequest to Router Port.')
                port_data = self.port_data.get_data(port_no=in_port)
                src_mac = port_data.mac
                dst_mac = header_list[ARP].src_mac
                src_ip = header_list[ARP].dst_ip
                dst_ip = header_list[ARP].src_ip
                arp_target_mac = dst_mac
                output = self.ofctl.dp.ofproto.OFPP_IN_PORT

                self.ofctl.send_arp(arp.ARP_REPLY, self.vlan_id,
                                    src_mac, dst_mac, src_ip, dst_ip,
                                    arp_target_mac, in_port, output)
            elif header_list[ARP].opcode == arp.ARP_REPLY:
                #  ARPreply to Router Port -> suspend packets forward
                log_debug(self.dp.id, 'receive ARPreply to Router Port.')
                src_ip = header_list[ARP].src_ip
                if src_ip in self.packet_buffer:
                    packet_list = self.packet_buffer[src_ip]
                    output = self.ofctl.dp.ofproto.OFPP_TABLE
                    for suspend_packet in packet_list:
                        self.ofctl.send_packet_out(suspend_packet.in_port,
                                                   output,
                                                   suspend_packet.data)
                    del self.packet_buffer[src_ip]
                    self.packet_buffer.length -= len(packet_list)

    def event_icmp_req(self, msg, header_list):
        # send ICMP echo reply.
        log_debug(self.dp.id, 'receive ICMPecho to Router Port.')
        in_port = self.ofctl.get_packetin_inport(msg)
        self.ofctl.send_icmp(in_port, header_list, self.vlan_id,
                             icmp.ICMP_ECHO_REPLY,
                             icmp.ICMP_ECHO_REPLY_CODE,
                             icmp_data=header_list[ICMP].data)

    def event_tcp_udp(self, msg, header_list):
        # send ICMP Port Unreach error.
        log_debug(self.dp.id, 'receive TCP/UDP to Router Port.')
        in_port = self.ofctl.get_packetin_inport(msg)
        self.ofctl.send_icmp(in_port, header_list, self.vlan_id,
                             icmp.ICMP_DEST_UNREACH,
                             icmp.ICMP_PORT_UNREACH_CODE,
                             msg_data=msg.data)

    def event_packetin_node(self, msg, header_list):
        if self.packet_buffer.length >= MAX_SUSPENDPACKETS:
            log_info(self.dp.id,
                     'Packet is dropped, MAX_SUSPENDPACKETS exceeded.')
            return

        # send ARP request to get node MAC address.
        in_port = self.ofctl.get_packetin_inport(msg)
        src_ip = None
        dst_ip = header_list[IPV4].dst

        address = self.address_data.get_data(dst_ip)
        if address is not None:
            log_debug(self.dp.id, 'receive IP packet to internal Host.')
            src_ip = address.default_route
        else:
            route = self.routing_tbl.get_data(dst_ip=dst_ip)
            if route is not None:
                log_debug(self.dp.id, 'receive IP packet to gateway Router.')
                gw_address = self.address_data.get_data(route.gateway_ip)
                if gw_address is not None:
                    src_ip = gw_address.default_route
                    dst_ip = route.gateway_ip

        if src_ip is not None:
            self.packet_buffer.add(in_port, dst_ip, header_list, msg.data)
            self.send_arp_request(src_ip, dst_ip, in_port=in_port)

    def event_invalid_ttl(self, msg, header_list):
        # send ICMP TTL error.
        log_debug(self.dp.id, 'receive Invalid TTL packet.')
        in_port = self.ofctl.get_packetin_inport(msg)
        src_ip = self._get_send_port_ip(header_list)
        if src_ip is not None:
            self.ofctl.send_icmp(in_port, header_list, self.vlan_id,
                                 icmp.ICMP_TIME_EXCEEDED,
                                 icmp.ICMP_TTL_EXPIRED_CODE,
                                 msg_data=msg.data, src_ip=src_ip)

    def send_arp_all_gw(self):
        gateways = self.routing_tbl.get_gateways()
        for gateway in gateways:
            address = self.address_data.get_data(gateway)
            self.send_arp_request(address.default_route, gateway)

    def send_arp_request(self, src_ip, dst_ip, in_port=None):
        # send ARP request from all ports.
        for send_port in self.port_data.values():
            if in_port is None or in_port != send_port.port_no:
                src_mac = send_port.mac
                dst_mac = mac_lib.BROADCAST
                arp_target_mac = mac_lib.DONTCARE
                inport = self.ofctl.dp.ofproto.OFPP_CONTROLLER
                output = send_port.port_no
                self.ofctl.send_arp(arp.ARP_REQUEST, self.vlan_id,
                                    src_mac, dst_mac, src_ip, dst_ip,
                                    arp_target_mac, inport, output)

    def send_icmp_unreach_error(self, packet_buffer_list):
        # send ICMP Host Unreach error.
        log_debug(self.dp.id, 'ARPreply wait Timer was timed out.')
        for packet_buffer in packet_buffer_list:
            src_ip = self._get_send_port_ip(packet_buffer.header_list)
            if src_ip is not None:
                self.ofctl.send_icmp(packet_buffer.in_port,
                                     packet_buffer.header_list,
                                     self.vlan_id,
                                     icmp.ICMP_DEST_UNREACH,
                                     icmp.ICMP_HOST_UNREACH_CODE,
                                     msg_data=packet_buffer.data,
                                     src_ip=src_ip)

    def _update_routing_tbl(self, msg, header_list):
        # set Flow: routing to Gateway.
        out_port = self.ofctl.get_packetin_inport(msg)
        port_data = self.port_data.get_data(port_no=out_port)
        src_mac = header_list[ARP].src_mac
        dst_mac = port_data.mac
        src_ip = header_list[ARP].src_ip

        gateway_flg = False
        for key, value in self.routing_tbl.items():
            if value.gateway_ip == src_ip:
                gateway_flg = True
                if value.gateway_mac == src_mac:
                    continue
                self.routing_tbl[key].gateway_mac = src_mac

                cookie = self._id_to_cookie(REST_ROUTEID, value.route_id)
                if value.dst_ip:
                    priority = PRIORITY_STATIC_ROUTING + value.netmask
                    log_msg = 'StaticRouting'
                else:
                    priority = PRIORITY_DEFAULT_ROUTING
                    log_msg = 'DefaultRouting'
                self.ofctl.set_routing_flow(cookie, priority, out_port,
                                            dl_vlan=self.vlan_id,
                                            src_mac=dst_mac,
                                            dst_mac=src_mac,
                                            nw_dst=value.dst_ip,
                                            dst_mask=value.netmask,
                                            dec_ttl=True)
                log_info(self.dp.id,
                         'Set %s Flow [cookie=0x%x]' % (log_msg, cookie))
        return gateway_flg

    def _learning_host_mac(self, msg, header_list):
        # set Flow: routing to internal Host.
        out_port = self.ofctl.get_packetin_inport(msg)
        port_data = self.port_data.get_data(port_no=out_port)
        src_mac = header_list[ARP].src_mac
        dst_mac = port_data.mac
        src_ip = header_list[ARP].src_ip

        gateways = self.routing_tbl.get_gateways()
        if src_ip not in gateways:
            address = self.address_data.get_data(src_ip)
            if address is not None:
                cookie = self._id_to_cookie(REST_ADDRESSID, address.address_id)
                self.ofctl.set_routing_flow(cookie, PRIORITY_IMPLICIT_ROUTING,
                                            out_port, dl_vlan=self.vlan_id,
                                            src_mac=dst_mac, dst_mac=src_mac,
                                            nw_dst=src_ip,
                                            idle_timeout=IDLE_TIMEOUT,
                                            dec_ttl=True)
                log_info(self.dp.id,
                         'Set ImplicitRouting Flow [cookie=0x%x]' % cookie)

    def _get_send_port_ip(self, header_list):
        try:
            src_mac = header_list[ETHERNET].src
            if IPV4 in header_list:
                src_ip = header_list[IPV4].src
            else:
                src_ip = header_list[ARP].src_ip
        except:
            log_debug(self.dp.id, 'Receive unsupported Packet.')
            return None

        address = self.address_data.get_data(src_ip)
        if address is not None:
            return address.default_route
        else:
            route = self.routing_tbl.get_data(gw_mac=src_mac)
            if route is not None:
                address = self.address_data.get_data(route.gateway_ip)
                if address is not None:
                    return address.default_route

        srcip = ip_addr_ntoa(src_ip)
        log_debug(self.dp.id, 'Receive Packet from unknown IP[%s].' % srcip)
        return None


class PortData(dict):
    def __init__(self, ports):
        super(PortData, self).__init__()
        for port in ports.values():
            data = Port(port.port_no, port.hw_addr)
            self.setdefault(port.port_no, data)

    def get_data(self, port_no=None, mac=None, ip=None):
        if port_no is not None:
            return self.get(port_no, None)
        for port in self.values():
            if ((mac is not None and mac == port.mac)
                    or (ip is not None and ip == port.ip)):
                return port
        return None


class Port(object):
    def __init__(self, port_no, hw_addr):
        super(Port, self).__init__()
        self.port_no = port_no
        self.mac = hw_addr


class AddressData(dict):
    def __init__(self):
        super(AddressData, self).__init__()
        self.address_id = 1

    def add(self, address):
        try:
            nw_addr, mask, default_route = nw_addr_aton(address)
        except ValueError:
            raise ValueError('Invalid [%s] value.' % REST_ADDRESS)

        # Check Overlap
        overlap_address = 0
        for other in self.values():
            other_mask = mask_ntob(other.netmask)
            add_mask = mask_ntob(mask)
            if (other.nw_addr == default_route & other_mask
                    or nw_addr == other.default_route & add_mask):
                overlap_address = other.address_id
                break
        if overlap_address:
            msg = 'Address overlaps [address_id=%d]' % overlap_address
            raise CommandFailure(msg=msg)

        address = Address(self.address_id, nw_addr, mask, default_route)
        ip_str = ip_addr_ntoa(nw_addr)
        key = '%s/%d' % (ip_str, mask)
        self[key] = address
        self.address_id += 1
        self.address_id &= ofproto_v1_2_parser.UINT32_MAX

        return address

    def delete(self, address_id):
        for key, value in self.items():
            if value.address_id == address_id:
                del self[key]

    def get_default_routes(self):
        default_routes = []
        for address in self.values():
            default_routes.append(address.default_route)
        return default_routes

    def get_data(self, ip):
        for address in self.values():
            if ip & mask_ntob(address.netmask) == address.nw_addr:
                return address
        return None


class Address(object):
    def __init__(self, address_id, nw_addr, netmask, default_route):
        super(Address, self).__init__()
        self.address_id = address_id
        self.nw_addr = nw_addr
        self.netmask = netmask
        self.default_route = default_route


class RoutingTable(dict):

    def __init__(self):
        super(RoutingTable, self).__init__()
        self.route_id = 1

    def add(self, dst_nw_addr, gateway_ip):
        if dst_nw_addr == DEFAULT_ROUTE:
            dst_ip = 0
            netmask = 0
        else:
            try:
                dst_ip, netmask, dummy = nw_addr_aton(dst_nw_addr)
            except ValueError:
                raise ValueError('Invalid [%s] value.' % REST_DESTINATION)
        try:
            gateway_ip = ip_addr_aton(gateway_ip)
        except ValueError:
            raise ValueError('Invalid [%s] value.' % REST_GATEWAY)

        # Check Overlap
        overlap_route = 0
        if dst_nw_addr == DEFAULT_ROUTE:
            if DEFAULT_ROUTE in self:
                overlap_route = self[DEFAULT_ROUTE].route_id
        elif dst_nw_addr in self:
            overlap_route = self[dst_nw_addr].route_id

        if overlap_route:
            msg = 'Destination overlaps [route_id=%d]' % overlap_route
            raise CommandFailure(msg=msg)

        routing_data = Route(self.route_id, dst_ip, netmask, gateway_ip)
        ip_str = ip_addr_ntoa(dst_ip)
        key = '%s/%d' % (ip_str, netmask)
        self[key] = routing_data
        self.route_id += 1

        return routing_data

    def delete(self, route_id):
        for key, value in self.items():
            if value.route_id == route_id:
                del self[key]
                return

    def get_gateways(self):
        gateways = []
        for routing_data in self.values():
            if routing_data.gateway_ip not in gateways:
                gateways.append(routing_data.gateway_ip)
        return gateways

    def get_data(self, gw_mac=None, dst_ip=None):
        if gw_mac is not None:
            for route in self.values():
                if gw_mac == route.gateway_mac:
                    return route
            return None

        elif dst_ip is not None:
            get_route = None
            mask = 0
            for route in self.values():
                if dst_ip & mask_ntob(route.netmask) == route.dst_ip:
                    # for longest match
                    if mask < route.netmask:
                        get_route = route
                        mask = route.netmask

            if get_route is None:
                get_route = self.get(DEFAULT_ROUTE, None)
            return get_route
        else:
            return None


class Route(object):
    def __init__(self, route_id, dst_ip, netmask, gateway_ip):
        super(Route, self).__init__()
        self.route_id = route_id & ofproto_v1_2_parser.UINT32_MAX
        self.dst_ip = dst_ip
        self.netmask = netmask
        self.gateway_ip = gateway_ip
        self.gateway_mac = None


class SuspendPacketList(dict):
    def __init__(self, timeout_function):
        super(SuspendPacketList, self).__init__()
        self.timeout_function = timeout_function
        self.length = 0

    def add(self, in_port, dst_ip, header_list, data):
        data = SuspendPacket(in_port, header_list, data)
        self.setdefault(dst_ip, [])
        self[dst_ip].append(data)
        self.length += 1

        # start ARPreply wait Timer.
        hub.spawn(self._wait_reply, dst_ip)

    def _wait_reply(self, key):
        hub.sleep(ARP_REPLY_TIMER)
        if key in self:
            self.timeout_function(self[key])
            del self[key]
            self.length -= 1


class SuspendPacket(object):
    def __init__(self, in_port, header_list, data):
        super(SuspendPacket, self).__init__()
        self.in_port = in_port
        self.header_list = header_list
        self.data = data


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
            ofctl = OfCtl._OF_VERSIONS[of_version](dp)
        else:
            raise OFPUnknownVersion(version=of_version)

        return ofctl

    def __init__(self, dp):
        super(OfCtl, self).__init__()
        self.dp = dp

    def set_sw_config_for_ttl(self):
        # OpenFlow v1_2 only.
        pass

    def set_flow(self, cookie, priority, dl_type=0, dl_dst=0, dl_vlan=0,
                 nw_src=0, src_mask=32, nw_dst=0, dst_mask=32,
                 nw_proto=0, idle_timeout=0, actions=None):
        # abstract method
        pass

    def send_arp(self, arp_opcode, vlan_id, src_mac, dst_mac,
                 src_ip, dst_ip, arp_target_mac, in_port, output):
        # generate ARP packet
        if vlan_id != VLANID_NONE:
            ether_proto = ether.ETH_TYPE_8021Q
            pcp = 0
            cfi = 0
            vlan_ether = ether.ETH_TYPE_ARP
            v = vlan.vlan(pcp, cfi, vlan_id, vlan_ether)
        else:
            ether_proto = ether.ETH_TYPE_ARP
        hwtype = 1
        arp_proto = ether.ETH_TYPE_IP
        hlen = 6
        plen = 4

        pkt = packet.Packet()
        e = ethernet.ethernet(dst_mac, src_mac, ether_proto)
        a = arp.arp(hwtype, arp_proto, hlen, plen, arp_opcode,
                    src_mac, src_ip, arp_target_mac, dst_ip)
        pkt.add_protocol(e)
        if vlan_id != VLANID_NONE:
            pkt.add_protocol(v)
        pkt.add_protocol(a)
        pkt.serialize()

        # send PacketOut
        self.send_packet_out(in_port, output, pkt.data, data_str=str(pkt))

    def send_icmp(self, in_port, protocol_list, vlan_id, icmp_type,
                  icmp_code, icmp_data=None, msg_data=None, src_ip=None):
        # generate ICMP reply packet
        csum = 0
        offset = ethernet.ethernet._MIN_LEN

        if vlan_id != VLANID_NONE:
            ether_proto = ether.ETH_TYPE_8021Q
            pcp = 0
            cfi = 0
            vlan_ether = ether.ETH_TYPE_IP
            v = vlan.vlan(pcp, cfi, vlan_id, vlan_ether)
            offset += vlan.vlan._MIN_LEN
        else:
            ether_proto = ether.ETH_TYPE_IP

        eth = protocol_list[ETHERNET]
        e = ethernet.ethernet(eth.src, eth.dst, ether_proto)

        if icmp_data is None and msg_data is not None:
            ip_datagram = msg_data[offset:]
            if icmp_type == icmp.ICMP_DEST_UNREACH:
                icmp_data = icmp.dest_unreach(data_len=len(ip_datagram),
                                              data=ip_datagram)
            elif icmp_type == icmp.ICMP_TIME_EXCEEDED:
                icmp_data = icmp.time_exceeded(data_len=len(ip_datagram),
                                               data=ip_datagram)

        ic = icmp.icmp(icmp_type, icmp_code, csum, data=icmp_data)

        ip = protocol_list[IPV4]
        if src_ip is None:
            src_ip = ip.dst
        ip_total_length = ip.header_length * 4 + ic._MIN_LEN
        if ic.data is not None:
            ip_total_length += ic.data._MIN_LEN
            if ic.data.data is not None:
                ip_total_length += + len(ic.data.data)
        i = ipv4.ipv4(ip.version, ip.header_length, ip.tos,
                      ip_total_length, ip.identification, ip.flags,
                      ip.offset, DEFAULT_TTL, inet.IPPROTO_ICMP, csum,
                      src_ip, ip.src)

        pkt = packet.Packet()
        pkt.add_protocol(e)
        if vlan_id != VLANID_NONE:
            pkt.add_protocol(v)
        pkt.add_protocol(i)
        pkt.add_protocol(ic)
        pkt.serialize()

        # send PacketOut
        self.send_packet_out(in_port, self.dp.ofproto.OFPP_IN_PORT,
                             pkt.data, data_str=str(pkt))

    def send_packet_out(self, in_port, output, data, data_str=None):
        actions = [self.dp.ofproto_parser.OFPActionOutput(output, 0)]
        self.dp.send_packet_out(buffer_id=0xffffffff, in_port=in_port,
                                actions=actions, data=data)
        if data_str is None:
            data_str = str(packet.Packet(data))
        log_msg = 'PacketOut = %s' % data_str
        log_info(self.dp.id, log_msg)

    def set_normal_flow(self, cookie, priority):
        out_port = self.dp.ofproto.OFPP_NORMAL
        actions = [self.dp.ofproto_parser.OFPActionOutput(out_port, 0)]
        self.set_flow(cookie, priority, actions=actions)

    def set_packetin_flow(self, cookie, priority, dl_type=0, dl_dst=0,
                          dl_vlan=0, dst_ip=0, dst_mask=32, nw_proto=0):
        miss_send_len = ofproto_v1_2_parser.UINT16_MAX
        actions = [self.dp.ofproto_parser.OFPActionOutput(
            self.dp.ofproto.OFPP_CONTROLLER, miss_send_len)]
        self.set_flow(cookie, priority, dl_type=dl_type, dl_dst=dl_dst,
                      dl_vlan=dl_vlan, nw_dst=dst_ip, dst_mask=dst_mask,
                      nw_proto=nw_proto, actions=actions)

    def send_stats_request(self, stats, waiters):
        self.dp.set_xid(stats)
        waiters_per_dp = waiters.setdefault(self.dp.id, {})
        event = hub.Event()
        msgs = []
        waiters_per_dp[stats.xid] = (event, msgs)
        self.dp.send_msg(stats)

        try:
            event.wait(timeout=OFP_REPLY_TIMER)
        except hub.Timeout:
            del waiters_per_dp[stats.xid]

        return msgs


@OfCtl.register_of_version(ofproto_v1_0.OFP_VERSION)
class OfCtl_v1_0(OfCtl):

    def __init__(self, dp):
        super(OfCtl_v1_0, self).__init__(dp)

    def get_packetin_inport(self, msg):
        return msg.in_port

    def get_all_flow(self, waiters):
        ofp = self.dp.ofproto
        ofp_parser = self.dp.ofproto_parser

        match = ofp_parser.OFPMatch(ofp.OFPFW_ALL, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0)
        stats = ofp_parser.OFPFlowStatsRequest(self.dp, 0, match,
                                               0xff, ofp.OFPP_NONE)
        return self.send_stats_request(stats, waiters)

    def set_flow(self, cookie, priority, dl_type=0, dl_dst=0, dl_vlan=0,
                 nw_src=0, src_mask=32, nw_dst=0, dst_mask=32,
                 nw_proto=0, idle_timeout=0, actions=None):
        ofp = self.dp.ofproto
        ofp_parser = self.dp.ofproto_parser
        cmd = ofp.OFPFC_ADD

        # Match
        wildcards = ofp.OFPFW_ALL
        if dl_type:
            wildcards &= ~ofp.OFPFW_DL_TYPE
        if dl_dst:
            wildcards &= ~ofp.OFPFW_DL_DST
        if dl_vlan:
            wildcards &= ~ofp.OFPFW_DL_VLAN
            priority += PRIORITY_VLAN_SHIFT
        if nw_src:
            v = (32 - src_mask) << ofp.OFPFW_NW_SRC_SHIFT | \
                ~ofp.OFPFW_NW_SRC_MASK
            wildcards &= v
        if nw_dst:
            v = (32 - dst_mask) << ofp.OFPFW_NW_DST_SHIFT | \
                ~ofp.OFPFW_NW_DST_MASK
            wildcards &= v
        if nw_proto:
            wildcards &= ~ofp.OFPFW_NW_PROTO

        match = ofp_parser.OFPMatch(wildcards, 0, 0, dl_dst, dl_vlan, 0,
                                    dl_type, 0, nw_proto, nw_src, nw_dst,
                                    0, 0)
        actions = actions or []

        m = ofp_parser.OFPFlowMod(self.dp, match, cookie, cmd,
                                  idle_timeout=idle_timeout,
                                  priority=priority, actions=actions)
        self.dp.send_msg(m)

    def set_routing_flow(self, cookie, priority, outport, dl_vlan=0,
                         nw_src=0, src_mask=32, nw_dst=0, dst_mask=32,
                         src_mac=0, dst_mac=0, idle_timeout=0, **dummy):
        ofp_parser = self.dp.ofproto_parser

        dl_type = ether.ETH_TYPE_IP

        # Decrement TTL value is not supported at OpenFlow V1.0
        actions = []
        if src_mac:
            actions.append(ofp_parser.OFPActionSetDlSrc(src_mac))
        if dst_mac:
            actions.append(ofp_parser.OFPActionSetDlDst(dst_mac))
        if outport is not None:
            actions.append(ofp_parser.OFPActionOutput(outport))

        self.set_flow(cookie, priority, dl_type=dl_type, dl_vlan=dl_vlan,
                      nw_src=nw_src, src_mask=src_mask,
                      nw_dst=nw_dst, dst_mask=dst_mask,
                      idle_timeout=idle_timeout, actions=actions)

    def delete_flow(self, flow_stats):
        match = flow_stats.match
        cookie = flow_stats.cookie
        cmd = self.dp.ofproto.OFPFC_DELETE_STRICT
        priority = flow_stats.priority
        actions = []

        flow_mod = self.dp.ofproto_parser.OFPFlowMod(
            self.dp, match, cookie, cmd, priority=priority, actions=actions)
        self.dp.send_msg(flow_mod)
        log_info(self.dp.id, 'Delete Flow [cookie=0x%x]' % cookie)


@OfCtl.register_of_version(ofproto_v1_2.OFP_VERSION)
class OfCtl_v1_2(OfCtl):

    def __init__(self, dp):
        super(OfCtl_v1_2, self).__init__(dp)

    def set_sw_config_for_ttl(self):
        flags = self.dp.ofproto.OFPC_INVALID_TTL_TO_CONTROLLER
        miss_send_len = ofproto_v1_2_parser.UINT16_MAX
        m = self.dp.ofproto_parser.OFPSetConfig(self.dp, flags,
                                                miss_send_len)
        self.dp.send_msg(m)
        log_info(self.dp.id, 'Set SWconfig for TTL error PacketIn.')

    def get_packetin_inport(self, msg):
        in_port = self.dp.ofproto.OFPP_ANY
        for match_field in msg.match.fields:
            if match_field.header == self.dp.ofproto.OXM_OF_IN_PORT:
                in_port = match_field.value
                break
        return in_port

    def get_all_flow(self, waiters):
        ofp = self.dp.ofproto
        ofp_parser = self.dp.ofproto_parser

        match = ofp_parser.OFPMatch()
        stats = ofp_parser.OFPFlowStatsRequest(self.dp, 0, ofp.OFPP_ANY,
                                               ofp.OFPG_ANY, 0, 0, match)
        return self.send_stats_request(stats, waiters)

    def set_flow(self, cookie, priority, dl_type=0, dl_dst=0, dl_vlan=0,
                 nw_src=0, src_mask=32, nw_dst=0, dst_mask=32,
                 nw_proto=0, idle_timeout=0, actions=None):
        ofp = self.dp.ofproto
        ofp_parser = self.dp.ofproto_parser
        cmd = ofp.OFPFC_ADD

        # Match
        match = ofp_parser.OFPMatch()
        if dl_type:
            match.set_dl_type(dl_type)
        if dl_dst:
            match.set_dl_dst(dl_dst)
        if dl_vlan:
            match.set_vlan_vid(dl_vlan)
            priority += PRIORITY_VLAN_SHIFT
        if nw_src:
            match.set_ipv4_src_masked(nw_src, mask_ntob(src_mask))
        if nw_dst:
            match.set_ipv4_dst_masked(nw_dst, mask_ntob(dst_mask))
        if nw_proto:
            if dl_type == ether.ETH_TYPE_IP:
                match.set_ip_proto(nw_proto)
            elif dl_type == ether.ETH_TYPE_ARP:
                match.set_arp_opcode(nw_proto)

        # Instructions
        actions = actions or []
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]

        m = ofp_parser.OFPFlowMod(self.dp, cookie, 0, 0, cmd, idle_timeout,
                                  0, priority, 0xffffffff, ofp.OFPP_ANY,
                                  ofp.OFPG_ANY, 0, match, inst)
        self.dp.send_msg(m)

    def set_routing_flow(self, cookie, priority, outport, dl_vlan=0,
                         nw_src=0, src_mask=32, nw_dst=0, dst_mask=32,
                         src_mac=0, dst_mac=0, idle_timeout=0, dec_ttl=False):
        ofp = self.dp.ofproto
        ofp_parser = self.dp.ofproto_parser

        dl_type = ether.ETH_TYPE_IP

        actions = []
        if dec_ttl:
            actions.append(ofp_parser.OFPActionDecNwTtl())
        if src_mac:
            set_src = ofp_parser.OFPMatchField.make(ofp.OXM_OF_ETH_SRC,
                                                    src_mac)
            actions.append(ofp_parser.OFPActionSetField(set_src))
        if dst_mac:
            set_dst = ofp_parser.OFPMatchField.make(ofp.OXM_OF_ETH_DST,
                                                    dst_mac)
            actions.append(ofp_parser.OFPActionSetField(set_dst))
        if outport is not None:
            actions.append(ofp_parser.OFPActionOutput(outport, 0))

        self.set_flow(cookie, priority, dl_type=dl_type, dl_vlan=dl_vlan,
                      nw_src=nw_src, src_mask=src_mask,
                      nw_dst=nw_dst, dst_mask=dst_mask,
                      idle_timeout=idle_timeout, actions=actions)

    def delete_flow(self, flow_stats):
        ofp = self.dp.ofproto
        ofp_parser = self.dp.ofproto_parser

        cmd = ofp.OFPFC_DELETE
        cookie = flow_stats.cookie
        cookie_mask = ofproto_v1_2_parser.UINT64_MAX
        match = ofp_parser.OFPMatch()
        inst = []

        flow_mod = ofp_parser.OFPFlowMod(self.dp, cookie, cookie_mask, 0, cmd,
                                         0, 0, 0, 0xffffffff, ofp.OFPP_ANY,
                                         ofp.OFPG_ANY, 0, match, inst)
        self.dp.send_msg(flow_mod)
        log_info(self.dp.id, 'Delete Flow [cookie=0x%x]' % cookie)


def ip_addr_aton(ip_str):
    try:
        return struct.unpack('!I', socket.inet_aton(ip_str))[0]
    except (struct.error, socket.error):
        raise ValueError()


def ip_addr_ntoa(ip):
    try:
        return socket.inet_ntoa(struct.pack('!I', ip))
    except (struct.error, socket.error):
        raise ValueError()


def mask_ntob(mask):
    return ofproto_v1_2_parser.UINT32_MAX << 32 - mask\
        & ofproto_v1_2_parser.UINT32_MAX


def nw_addr_aton(nw_addr):
    ip_mask = nw_addr.split('/')
    default_route = ip_addr_aton(ip_mask[0])
    netmask = 32
    if len(ip_mask) == 2:
        netmask = int(ip_mask[1])
    if netmask < 0:
        raise ValueError()
    nw_addr = default_route & mask_ntob(netmask)
    return nw_addr, netmask, default_route
