#!/bin/bash

#echo "sudo ovs-vsctl set Bridge s1 protocols=OpenFlow13 && sudo ovs-vsctl set Bridge s2 protocols=OpenFlow13"
#
#sudo ovs-vsctl set Bridge s1 protocols=OpenFlow13 && \
#sudo ovs-vsctl set Bridge s2 protocols=OpenFlow13

echo "sudo ovs-vsctl add-port s1 s1-snort && sudo ovs-ofctl show s1 && sudo ovs-vsctl add-port s2 s2-snort && sudo ovs-ofctl show s2"

sudo ovs-vsctl add-port s1 s1-snort && \
sudo ovs-ofctl show s1 && \
sudo ovs-vsctl add-port s2 s2-snort && \
sudo ovs-ofctl show s2