# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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



import base64
import json
import logging
import os
import sys

from ryu import log
from ryu.base import app_manager
from ryu.controller import controller
from ryu.controller import handler
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.exception import RyuException
from ryu.lib import dpid as dpid_lib
from ryu.lib import hub
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp
from ryu.lib.packet import icmpv6
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import mpls
from ryu.lib.packet import packet
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import vlan
from ryu.ofproto import ofproto_parser
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser


""" Required test network.

                      +---------+
           +-------(3)| test sw | The switch to test
           |          +---------+
    +------------+     (1)   (2)
    | controller |      |     |
    +------------+     (1)   (2)
           |          +---------+
           +-------(3)| sub sw  | Open vSwtich
                      +---------+

      (X) : port number

"""


DEFAULT_DIRECTORY = './'

TEST_SW_ID = dpid_lib.str_to_dpid('0000000000000001')
SUB_SW_ID = dpid_lib.str_to_dpid('0000000000000002')

WAIT_TIMER = 5  # sec


# Test result.
OK = 'OK'
TEST_FILE_ERROR = '%s : Test file format error.'
STATS_REPLY_NOTHING = 'NG (OFPFlowStatsReply is not coming.)'
FLOW_INSTALL_ERROR = 'NG (flow was not installed.)'


_PROTOCOL_STACK = {
    'arp': arp.arp,
    'ethernet': ethernet.ethernet,
    'icmp': icmp.icmp,
    'icmpv6': icmpv6.icmpv6,
    'ipv4': ipv4.ipv4,
    'ipv6': ipv6.ipv6,
    'mpls': mpls.mpls,
    'tcp': tcp.tcp,
    'udp': udp.udp,
    'vlan': vlan.vlan,
}


def main():
    log.init_log()

    app_lists = ['of_tester',
                 'ryu.controller.ofp_handler']
    app_mgr = app_manager.AppManager()
    app_mgr.load_apps(app_lists)
    contexts = app_mgr.create_contexts()
    app_mgr.instantiate_apps(**contexts)

    ctlr = controller.OpenFlowController()
    thr = hub.spawn(ctlr)

    try:
        hub.joinall([thr])
    finally:
        app_mgr.close()


if __name__ == "__main__":
    main()


class TestEnvironmentError(RyuException):
    message = 'dpid=%(dpid)s : At least three links are required.'


class OfTester(app_manager.RyuApp):
    """ OpenFlowSwitch Tester. """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self):
        super(OfTester, self).__init__()
        self._set_logger()
        self.test_sw = None
        self.sub_sw = None
        self.test_thread = None
        self.waiter = None
        self.test_directory = (sys.argv[1] if len(sys.argv) > 1
                               else DEFAULT_DIRECTORY)
        if self.test_directory[-1:] != '/':
            self.test_directory += '/'
        self.logger.info('Test directory = \'%s\'', self.test_directory)

    def _set_logger(self):
        self.logger.propagate = False
        hdlr = logging.StreamHandler()
        fmt_str = '[%(levelname)s] %(message)s'
        hdlr.setFormatter(logging.Formatter(fmt_str))
        self.logger.addHandler(hdlr)

    def close(self):
        #TODO: kill all threads.
        if self.test_thread is not None:
            hub.kill(self.test_thread)
            hub.joinall([self.test_thread])
            self.test_thread = None

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [handler.MAIN_DISPATCHER, handler.DEAD_DISPATCHER])
    def dispacher_change(self, ev):
        assert ev.datapath is not None
        if ev.state == handler.MAIN_DISPATCHER:
            self._register_sw(ev.datapath)
        elif ev.state == handler.DEAD_DISPATCHER:
            self._unregister_sw(ev.datapath)

    def _register_sw(self, dp):
        try:
            if dp.id == TEST_SW_ID:
                self.test_sw = TestSw(dp, self.logger)
                self.logger.info('dpid=%s : Join test SW.',
                                 dpid_lib.dpid_to_str(dp.id))
            elif dp.id == SUB_SW_ID:
                self.sub_sw = SubSw(dp, self.logger)
                self.logger.info('dpid=%s : Join sub SW.',
                                 dpid_lib.dpid_to_str(dp.id))
        except TestEnvironmentError as err:
            self.logger.error(str(err))
            return

        if self.test_sw and self.sub_sw:
            self.test_thread = hub.spawn(self._test_execute)

    def _unregister_sw(self, dp):
        if dp.id == TEST_SW_ID:
            del self.test_sw
            self.test_sw = None
            self.logger.info('dpid=%s : Leave test SW.',
                             dpid_lib.dpid_to_str(dp.id))
        elif dp.id == SUB_SW_ID:
            del self.sub_sw
            self.sub_sw = None
            self.logger.info('dpid=%s : Leave sub SW.',
                             dpid_lib.dpid_to_str(dp.id))

    def _test_execute(self):
        tests = self._get_tests(self.test_directory, tests=[])
        if not tests:
            self.logger.warning('Test file (*.json) is not found.')
            return

        self.logger.info('--- Test start ---')
        for test in tests:
            if not test.flows:
                result = TEST_FILE_ERROR
            else:
                for flow in test.flows:
                    # 1. Install test flow.
                    self.test_sw.add_flow(flow_mod=flow)
                    #TODO: barrier request?
                    # 2. Check the installation result of test flow.
                    result = self._check_flow_exist(flow)
                    if result is not OK:
                        break

            if result is OK:
                # 3. Check flow matching.
                result = self._check_flow_matching(test.input_packet,
                                                   test.matched)

            # Output test result.
            self.logger.info('%s : %s', test.name, result)

            self.test_sw.del_test_flow()  # Delete test flow for next test.
        self.logger.info('---  Test end  ---')

    def _get_tests(self, test_dir, tests):
        test_path_list = os.listdir(test_dir)
        for test_path in test_path_list:
            path = test_dir + test_path
            if os.path.isdir(path):  # Directory
                path += '/'
                tests = self._get_tests(path, tests)
            elif os.path.isfile(path):  # File
                (dummy, ext) = os.path.splitext(path)
                if ext == '.json':
                    buf = open(path, 'rb').read()
                    try:
                        json_list = json.loads(
                            buf, object_hook=self._check_test_file)
                        for i, test_json in enumerate(json_list):
                            if len(json_list) == 1:
                                i = None
                            tests.append(Test(path, i, test_json))
                    except ValueError:
                        self.logger.warning(TEST_FILE_ERROR, path)
        return tests

    def _check_test_file(self, buf):
        add_items = {}
        del_keys = []
        for k, v in buf.iteritems():
            if -1 != k.find("_base64"):
                new_k = k.replace("_base64", "")
                add_items[new_k] = base64.b64decode(v)
                del_keys.append(k)
        for k in del_keys:
            del buf[k]
        for k, v in add_items.items():
            buf[k] = v
        return buf

    def _check_flow_exist(self, flow_mod):
        self.test_sw.send_flow_stats()

        wait_event = hub.Event()
        msgs = []
        self.waiter = [wait_event, msgs]
        timer = hub.Timeout(WAIT_TIMER)
        try:
            wait_event.wait()
            result = OK
        except hub.Timeout as t:
            if t is not timer:
                err_msg = 'Internal error. Not my timeout.'
                raise RyuException(msg=err_msg)
            result = STATS_REPLY_NOTHING
        finally:
            timer.cancel()
            wait_event = None

        if result is OK:
            result = FLOW_INSTALL_ERROR
            for msg in msgs:
                for stats in msg.body:
                    if self._compare_flow(stats, flow_mod):
                        result = OK
                        break

        self.waiter = None
        return result

    def _check_flow_matching(self, send_packet, is_match):
        pass

    def _compare_flow(self, stats, flow_mod):
        compare_list = [[stats.cookie, flow_mod.cookie],
                        [stats.priority, flow_mod.priority],
                        [stats.flags, flow_mod.flags],
                        [stats.hard_timeout, flow_mod.hard_timeout],
                        [stats.idle_timeout, flow_mod.idle_timeout],
                        [stats.table_id, flow_mod.table_id],
                        [str(stats.instructions),
                         str(flow_mod.instructions)],
                        [str(stats.match), str(flow_mod.match)]]
        for value in compare_list:
            if value[0] != value[1]:
                return False
        return True

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, handler.MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        if self.waiter is not None:
            (wait_event, msgs) = self.waiter
            msgs.append(ev.msg)
            if ev.msg.flags & ev.msg.datapath.ofproto.OFPMPF_REPLY_MORE:
                return
            wait_event.set()

    @set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        if self.test_sw and self.sub_sw:
            if ev.msg.datapath.id == self.test_sw.dp.id:
                pass
            elif ev.msg.datapath.id == self.sub_sw.dp.id:
                pass

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [handler.HANDSHAKE_DISPATCHER,
                                              handler.CONFIG_DISPATCHER,
                                              handler.MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        self.logger.error('dpid=%s : OFPErrorMsg received.'
                          ' type=0x%02x code=0x%02x message=%s',
                          dpid_lib.dpid_to_str(dp.id),
                          msg.type, msg.code, repr(msg.data))


class OpenFlowSw(object):
    def __init__(self, dp, logger):
        super(OpenFlowSw, self).__init__()
        self.dp = dp
        self.logger = logger
        if len(dp.ports) < 3:
            raise TestEnvironmentError(dpid=dpid_lib.dpid_to_str(dp.id))

    def add_flow(self, flow_mod=None, in_port=None, out_port=None):
        """ Add flow. """
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser

        if flow_mod:
            mod = flow_mod
        else:
            match = (parser.OFPMatch(in_port=in_port) if in_port
                     else parser.OFPMatch())
            max_len = (0 if out_port != ofp.OFPP_CONTROLLER
                       else ofp.OFPCML_MAX)
            actions = [parser.OFPActionOutput(out_port, max_len)]
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
            mod = parser.OFPFlowMod(self.dp, cookie=0,
                                    command=ofp.OFPFC_ADD,
                                    match=match, instructions=inst)
        self.dp.send_msg(mod)

    def del_flow(self):
        """ Delete all flow. """
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        mod = parser.OFPFlowMod(self.dp, command=ofp.OFPFC_DELETE)
        self.dp.send_msg(mod)

    def send_flow_stats(self):
        """ Get all flow. """
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        req = parser.OFPFlowStatsRequest(self.dp, 0, ofp.OFPTT_ALL,
                                         ofp.OFPP_ANY, ofp.OFPG_ANY,
                                         0, 0, parser.OFPMatch())
        self.dp.send_msg(req)


class TestSw(OpenFlowSw):
    def __init__(self, dp, logger):
        super(TestSw, self).__init__(dp, logger)
        # Add table miss flow (packet in controller).
        ofp = self.dp.ofproto
        self.add_flow(out_port=ofp.OFPP_CONTROLLER)

    def del_test_flow(self):
        ofp = self.dp.ofproto
        self.del_flow()
        self.add_flow(out_port=ofp.OFPP_CONTROLLER)


class SubSw(OpenFlowSw):
    def __init__(self, dp, logger):
        super(SubSw, self).__init__(dp, logger)
        # Add packet in flow.
        ofp = self.dp.ofproto
        self.add_flow(in_port=2, out_port=ofp.OFPP_CONTROLLER)


class Test(object):
    def __init__(self, test_file_path, number, test_json):
        super(Test, self).__init__()
        self.name = test_file_path.rstrip('.json')
        if number is not None:
            self.name += '_%d' % number
        (self.flows,
         self.input_packet,
         self.output_packet,
         self.matched) = self._parse_test(test_json)

    def _parse_test(self, buf):
        if (not 'flows' in buf or
                not 'input' in buf or
                not 'output' in buf or
                not 'matched' in buf):
            raise ValueError()

        # parse 'flows'
        flows = []
        for flow in buf['flows']:
            for k, v in flow.iteritems():
                cls = getattr(ofproto_v1_3_parser, k)
                msg = cls.from_jsondict(v, datapath=DummyDatapath())
                msg.version = ofproto_v1_3.OFP_VERSION
                msg.msg_type = msg.cls_msg_type
                msg.xid = 0
                flows.append(msg)
        if not flows:
            raise ValueError()

        # parse 'input'
        input_packet = packet.Packet()
        for protocol in buf['input']:
            for k, v in protocol.iteritems():
                cls_ = _PROTOCOL_STACK.get(k)
                if cls_:
                    p = cls_.from_jsondict(v, decode_string=str)
                else:
                    p = v
                input_packet.add_protocol(p)
        input_packet.serialize()

        # parse 'output'
        output_packet = packet.Packet()
        for protocol in buf['output']:
            for k, v in protocol.iteritems():
                cls_ = _PROTOCOL_STACK.get(k)
                if cls_:
                    p = cls_.from_jsondict(v, decode_string=str)
                else:
                    p = v
                output_packet.add_protocol(p)
        output_packet.serialize()

        #TODO:
        # parse 'matched'
        matched = True

        return (flows, input_packet, output_packet, matched)


class DummyDatapath(object):
    def __init__(self):
        self.ofproto = ofproto_v1_3
        self.ofproto_parser = ofproto_v1_3_parser
