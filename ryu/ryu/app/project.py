import array

from simple_switch_snort import SimpleSwitchSnort

from ryu.lib.packet import packet, ethernet, ipv4, icmp, tcp, udp
from ryu.lib import snortlib
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls


class Project(SimpleSwitchSnort):

    def __init__(self, *args, **kwargs):
        super(Project, self).__init__(*args, **kwargs)

    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        msg = ev.msg
        print('alertmsg: %s' % msg.alertmsg[0].decode())
        pkt = packet.Packet(array.array('B', msg.pkt))
        self.print_packet_data(pkt)

    def print_packet_data(self, pkt):
        eth = pkt.get_protocol(ethernet.ethernet)
        _ipv4 = pkt.get_protocol(ipv4.ipv4)
        _icmp = pkt.get_protocol(icmp.icmp)
        _tcp = pkt.get_protocol(tcp.tcp)
        _udp = pkt.get_protocol(udp.udp)

        self.logger.info("Ethernet: %r", eth)
        if _ipv4:
            self.logger.info("IP: %r", _ipv4)
        if _icmp:
            self.logger.info("ICMP: %r", _icmp)
        if _tcp:
            self.logger.info("TCP: %r", _tcp)
        if _udp:
            self.logger.info("UDP: %r", _udp)
