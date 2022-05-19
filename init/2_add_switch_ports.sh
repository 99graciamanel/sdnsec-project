#!/bin/bash

sudo ovs-vsctl add-port s1 s1-snort && \
sudo ovs-ofctl show s1 && \
sudo ovs-vsctl add-port s2 s2-snort && \
sudo ovs-ofctl show s2