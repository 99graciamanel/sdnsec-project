
from mininet.topo import Topo


class MyTopo(Topo):
    def __init__(self):
        # Initialize topology
        Topo.__init__(self)
        # Add hosts and switches
        h_inet = self.addHost('h_inet')    
        h_dmz = self.addHost('h_dmz')
        h_hp = self.addHost('h_hp')
        h_lan = self.addHost('h_lan')

        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        # Add (bidirectional) links from host to switches
        self.addLink(h_inet, s1)
        self.addLink(h_lan, s2)
        self.addLink(h_dmz, s1)
        self.addLink(h_hp, s1)

        # Add (bidirectional) links between switches
        self.addLink(s1, s2)

# Adding the 'topos' dict with a key/value pair to
# generate our newly defined topology enables one
# to pass in '--topo=mytopo' from the command line.
topos = {'mytopo': (lambda: MyTopo())}
