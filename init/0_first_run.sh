#!/bin/bash

sudo systemctl restart influxdb && \
sudo systemctl restart telegraf && \
sudo systemctl restart grafana-server && \
sudo systemctl restart snort

sudo ip link add name s1-snort type dummy && \
sudo ip link set s1-snort up && \
sudo ip link add name s2-snort type dummy && \
sudo ip link set s2-snort up

sudo cp ../snort/*conf /etc/snort/ && \
sudo chown snort:snort /etc/snort/*.conf && \
sudo cp ../snort/*rules /etc/snort/rules/
