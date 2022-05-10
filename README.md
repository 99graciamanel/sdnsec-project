# SDNSec Project

## Installation

sudo apt-get install mininet -y

## Configs

Copiar el telegraf.conf y ojo amb el /etc/snort/rules/*.rules

## Services

```
sudo apt install hping3 -y && \
sudo systemctl restart influxdb && \
sudo systemctl restart telegraf && \
sudo systemctl restart grafana-server && \
sudo systemctl restart snort
```

## Create snort interface

```
sudo ip link add name s1-snort type dummy && \
sudo ip link set s1-snort up
```

## Execute MiniNet

```
sudo mn -c && \
sudo mn --topo single,3 --mac --controller remote --switch ovsk
```
## Configure Mininet (set OpenFlow13 protocol and add port to switch s1 for snort)


Crec que s'hauria de fer `sudo ovs-vsctl set Bridge s1 protocols=OpenFlow13` però aleshores no funciona lo altre...

```
sudo ovs-vsctl add-port s1 s1-snort && \
sudo ovs-ofctl show s1
```

## Run RYU application

sudo ryu-manager ryu/ryu/app/rest_firewall.py ryu/ryu/app/simple_switch_snort.py simple_monitor_13_telegraf.py

He tret el `ryu/ryu/app/rest_firewall.py` perquè si no no es poden fer proves ??¿?¿¿?¿?¿

sudo ryu-manager ryu/ryu/app/simple_switch_snort.py ryu/ryu/app/simple_monitor_13.py simple_monitor_13_telegraf.py

```
sudo ryu-manager ryu/ryu/app/simple_switch_snort.py ryu/ryu/app/simple_monitor_13.py
```

## Run SNORT

```
sudo snort -i s1-snort -A unsock -l /tmp -c /etc/snort/snort.conf
```

## Influx

```
influx
show databases
use RYU
show measurements
select * from test_measurement where time > now() - 60m
```

## Attack

```
h1 python3 dos.py h2
```
