import array
import os

from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib import snortlib
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, tcp, udp

from simple_switch_snort import SimpleSwitchSnort

import requests


class Project(SimpleSwitchSnort):
    ICMP_FLOOD = "0"

    def __init__(self, *args, **kwargs):
        super(Project, self).__init__(*args, **kwargs)

    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        msg = ev.msg
        self.logger.info('alertmsg: %s' % msg.alertmsg[0].decode())
        pkt = packet.Packet(array.array('B', msg.pkt))
        self.print_packet_data(pkt)
        if pkt.get_protocol(icmp.icmp):
            self.fw_block_icmp(pkt)
        else:
            print()

    def fw_block_icmp(self, pkt):
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        self.fw_deny(_ipv4.src, _ipv4.dst, "ICMP")

    def fw_deny(self, src, dst, proto):
        self.logger.info("curl -X POST -d '{\"nw_src\": \"%s/32\", \"nw_dst\": \"%s/32\", \"nw_proto\": \"%s\", \"actions\":\"DENY\", \"priority\": \"10\"}' http://localhost:8080/firewall/rules/0000000000000001" % (src, dst, proto))
        os.system("curl -X POST -d '{\"nw_src\": \"%s/32\", \"nw_dst\": \"%s/32\", \"nw_proto\": \"%s\", \"actions\":\"DENY\", \"priority\": \"10\"}' http://localhost:8080/firewall/rules/0000000000000001" % (src, dst, proto))

        url = 'http://localhost:8080/firewall/rules/0000000000000001'
        data = {
            "nw_src": "%s" % src,
            "nw_dst": "%s" % dst,
            "nw_proto": "%s" % proto,
            "actions": "DENY",
            "priority": "10"
        }
        self.logger.info(data)
        response = requests.post(url, data=data)
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
