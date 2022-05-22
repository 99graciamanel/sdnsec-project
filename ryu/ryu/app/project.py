import array

from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib import snortlib
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, tcp, udp

from ryu.controller import ofp_event

from ryu.lib.packet.ether_types import ETH_TYPE_IP

from simple_switch_snort import SimpleSwitchSnort

import requests
import json
import socket
import datetime

class Project(SimpleSwitchSnort):
    ICMP_FLOOD = "0"

    DMZ_IP = '10.0.0.1'
    DMZ_MAC = '00:00:00:00:00:01'
    DMZ_PORT = 2

    HONEYPOT_IP = '10.0.0.2'
    HONEYPOT_MAC = '00:00:00:00:00:02'
    HONEYPOT_PORT = 3

    INTERNET_IP = '10.0.0.3'
    INTERNET_MAC = '00:00:00:00:00:03'
    INTERNET_PORT = 1

    UDP_IP = "127.0.0.1"
    UDP_PORT = 8094

    def __init__(self, *args, **kwargs):
        super(Project, self).__init__(*args, **kwargs)
        self.snort_port = 5
        self.is_redirecting_to_honeypot = False

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        if self.is_redirecting_to_honeypot and _ipv4 and _ipv4.src == self.INTERNET_IP and _ipv4.dst == self.DMZ_IP:
            self.redirect_to_honeypot(msg, pkt)
            return

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port),
                   parser.OFPActionOutput(self.snort_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        msg = ev.msg
        pkt = packet.Packet(array.array('B', msg.pkt))
        alert_msg = int(msg.alertmsg[0].decode()[0:3])
        
        sw_id = str(int(alert_msg/100))
        if alert_msg%100 == 1:
            proto = "ICMP"
        elif alert_msg%100 == 2:
            proto = "TCP"
        else:
            print(alert_msg)
            return

        self.print_packet_data(pkt)

        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        if _ipv4 and _ipv4.src == self.INTERNET_IP and _ipv4.dst == self.DMZ_IP:
            self.logger.info("is_redirecting_to_honeypot = True")
            self.is_redirecting_to_honeypot = True
            self.fw_controller(_ipv4.src, _ipv4.dst, "ICMP")
        else:
            self.optimistic_fw_block(ev, pkt, proto, sw_id)

    def optimistic_fw_block(self, ev, pkt, proto, sw_id):
        _ipv4 = pkt.get_protocol(ipv4.ipv4)

        if self.fw_check(_ipv4.src, _ipv4.dst, proto, sw_id):
            self.fw_deny(_ipv4.src, _ipv4.dst, proto, sw_id)

        #self.influx(ev)

    def fw_check(self, nw_src, nw_dst, nw_proto, sw_id):
        priority = 10

        url = 'http://localhost:8080/firewall/rules/000000000000000' + sw_id
        response = requests.get(url)
        data = response.text
        data_json = json.loads(data)

        self.logger.info(data_json)

        if len(data_json[0].get('access_control_list')) == 0:
            return True

        for json_rule in data_json[0].get('access_control_list')[0].get('rules'):
            if nw_src == json_rule.get('nw_src') and nw_dst == json_rule.get('nw_dst') and priority == json_rule.get(
                    'priority') and nw_proto == json_rule.get('nw_proto'):
                return False
        return True

    def fw_deny(self, src, dst, proto, sw_id):
        url = 'http://localhost:8080/firewall/rules/000000000000000%s' % str(sw_id)
        data = {
            "nw_src": "%s" % src,
            "nw_dst": "%s" % dst,
            "nw_proto": "%s" % proto,
            "actions": "DENY",
            "priority": "10"
        }

        requests.post(url, json=data)

    def fw_controller(self, src, dst, proto):
        url = 'http://localhost:8080/firewall/rules/0000000000000001'
        data = {
            "nw_src": "%s" % src,
            "nw_dst": "%s" % dst,
            "nw_proto": "%s" % proto,
            "actions": "PACKETIN",
            "priority": "15"
        }

        self.logger.info(data)
        response = requests.post(url, json=data)
        self.logger.info(response.text)

    def redirect_to_honeypot(self, msg, pkt):
        self.logger.info("Redirect to Honeypot")
        _eth = pkt.get_protocol(ethernet.ethernet)
        _ipv4 = pkt.get_protocol(ipv4.ipv4)

        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Incoming packets

        match = parser.OFPMatch(eth_type=ETH_TYPE_IP,
                                ip_proto=_ipv4.proto,
                                ipv4_src=self.INTERNET_IP,
                                ipv4_dst=self.DMZ_IP)
        actions = [
            parser.OFPActionSetField(ipv4_dst=self.HONEYPOT_IP),
            parser.OFPActionSetField(eth_dst=self.HONEYPOT_MAC),
            parser.OFPActionOutput(self.HONEYPOT_PORT)
        ]
        self.add_flow(datapath, 20, match, actions)

        # Outgoing packets

        match = parser.OFPMatch(eth_type=ETH_TYPE_IP,
                                ip_proto=_ipv4.proto,
                                ipv4_src=self.HONEYPOT_IP,
                                ipv4_dst=self.INTERNET_IP)
        actions = [
            parser.OFPActionSetField(ipv4_src=self.DMZ_IP),
            parser.OFPActionSetField(eth_src=self.DMZ_MAC),
            parser.OFPActionOutput(self.INTERNET_PORT)
        ]
        self.add_flow(datapath, 20, match, actions)

    def print_packet_data(self, pkt):
        _eth = pkt.get_protocol(ethernet.ethernet)
        _arp = pkt.get_protocol(arp.arp)
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        _icmp = pkt.get_protocol(icmp.icmp)
        _tcp = pkt.get_protocol(tcp.tcp)
        _udp = pkt.get_protocol(udp.udp)

        self.logger.info("Ethernet: %r", _eth)
        if _arp:
            self.logger.info("ARP: %r", _arp)
        if _ipv4:
            self.logger.info("IP: %r", _ipv4)
            self.logger.info("IP Source: %s", _ipv4.src)
            self.logger.info("IP Destination: %s", _ipv4.dst)
        if _icmp:
            self.logger.info("ICMP: %r", _icmp)
        if _tcp:
            self.logger.info("TCP: %r", _tcp)
        if _udp:
            self.logger.info("UDP: %r", _udp)

    def influx(self, ev):
        DETECTIONS_MSG = "detections,switch=\"%016x\" ipv4_src=\"%s\",ipv4_dst=\"%s\",packets=%d,bytes=%d %d"
        body = ev.msg.body
        self.logger.info(body)
        # self.logger.info('stats received: %016x', ev.msg.datapath.id)
        #
        # OFPFlowStats(byte_count=536328828, cookie=21, duration_nsec=763000000, duration_sec=3091, flags=0,
        #              hard_timeout=0, idle_timeout=0, instructions=[], length=80, match=OFPMatch(
        #         oxm_fields={'eth_type': 2048, 'ipv4_src': '10.0.0.3', 'ipv4_dst': '10.0.0.4', 'ip_proto': 1}),
        #              packet_count=371934, priority=10, table_id=0),

        self.logger.info(len(body))
        flows = [flow for flow in body if (flow.match and flow.priority >= 10 and flow.priority <= 20)]
        self.logger.info(len(flows))

        for stat in flows:
            self.logger.info(stat)
            timestamp = int(datetime.datetime.now().timestamp() * 1000000000)
            msg = DETECTIONS_MSG % (ev.msg.datapath.id,
                                    stat.match['ipv4_src'],
                                    stat.match['ipv4_dst'],
                                    stat.packet_count,
                                    stat.byte_count,
                                    timestamp)

            self.logger.info(msg)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(msg.encode(), (self.UDP_IP, self.UDP_PORT))
