#!/bin/bash

echo "sudo mn -c && sudo mn --custom ../topo/projectTopo.py --topo=projectTopo"

sudo mn -c && \
sudo mn --custom ../topo/projectTopo.py --topo=projectTopo