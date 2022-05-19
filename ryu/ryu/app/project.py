import array
import os
from time import sleep

from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib import snortlib
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, tcp, udp

from ryu.controller import ofp_event
from simple_switch_snort import SimpleSwitchSnort

import requests


class Project(SimpleSwitchSnort):
    ICMP_FLOOD = "0"

    def __init__(self, *args, **kwargs):
        super(Project, self).__init__(*args, **kwargs)
        self.snort_port = 4

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
        self.logger.info('alertmsg: %s' % msg.alertmsg[0].decode())
        pkt = packet.Packet(array.array('B', msg.pkt))
        self.print_packet_data(pkt)
        # if pkt.get_protocol(icmp.icmp):
        self.fw_block_icmp(pkt)

    def fw_block_icmp(self, pkt):
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        self.fw_deny(_ipv4.src, _ipv4.dst, "ICMP")

    def fw_deny(self, src, dst, proto):
        url = 'http://localhost:8080/firewall/rules/0000000000000001'
        data = {
            "nw_src": "%s" % src,
            "nw_dst": "%s" % dst,
            "nw_proto": "%s" % proto,
            "actions": "DENY",
            "priority": "10"
        }
        self.logger.info(data)
        response = requests.post(url, json=data)
        self.logger.info(response.text)

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
