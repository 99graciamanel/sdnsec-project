#!/bin/bash

echo "sudo mn -c && sudo mn --custom ../topo/projectTopo.py --mac --controller remote --topo=projectTopo"

sudo mn -c && \
sudo mn --custom ../topo/projectTopo.py --mac --controller remote --topo=projectTopo
