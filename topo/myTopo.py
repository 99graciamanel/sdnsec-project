
from mininet.topo import Topo


class MyTopo(Topo):
    def __init__(self):
        # Initialize topology
        Topo.__init__(self)
        # Add hosts and switches
        h1 = self.addHost('h1')    #Internet host
        h2 = self.addHost('h2')    #Lan host
        h3 = self.addHost('h3')    #DMZ host
        h4 = self.addHost('h4')    #Honeypot host

        s1 = self.addSwitch('s1')    #Firewall + snort switch
        s2 = self.addSwitch('s2')    #Firewall2 switch

        # Add (bidirectional) links from host to switches
        self.addLink(h1, s1)
        self.addLink(h2, s2)
        self.addLink(h3, s1)
        self.addLink(h3, s2)
        self.addLink(h4, s1)
        self.addLink(h4, s2)

        # Add (bidirectional) links between switches
        self.addLink(s1, s2)

# Adding the 'topos' dict with a key/value pair to
# generate our newly defined topology enables one
# to pass in '--topo=mytopo' from the command line.
topos = {'mytopo': (lambda: MyTopo())}
