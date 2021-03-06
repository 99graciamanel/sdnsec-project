# SDNSec Project

## Demonstration

### Step 1: Run Mininet

```
sudo systemctl restart influxdb && \
sudo systemctl restart telegraf && \
sudo systemctl restart grafana-server && \
sudo systemctl restart snort
```

```
sudo ip link add name s1-snort type dummy && \
sudo ip link set s1-snort up && \
sudo ip link add name s2-snort type dummy && \
sudo ip link set s2-snort up
```

```
sudo mn -c && \
sudo mn --custom topo/projectTopo.py --mac --controller remote --topo=projectTopo
```

### Step 2: Connect switch ports

```
sudo ovs-vsctl add-port s1 s1-snort && \
sudo ovs-ofctl show s1 && \
sudo ovs-vsctl add-port s2 s2-snort && \
sudo ovs-ofctl show s2
```

### Step 3: Run Snort 1

```
sudo snort -i s1-snort -A unsock -l /tmp/snort_s1 -c /etc/snort/snort_s1.conf
```

### Step 4: Run Snort 2

```
sudo snort -i s2-snort -A unsock -l /tmp/snort_s2 -c /etc/snort/snort_s2.conf
```

### Step 5: Run Ryu

```
sudo ryu-manager ryu/ryu/app/project.py ryu/ryu/app/rest_firewall.py ryu/ryu/app/simple_monitor_13_telegraf.py
```

### Step 6: Initialize Firewall

```
./init/set_up_firewall.sh
```

## Experiments

### Installation

```
sudo apt-get install mininet -y && \
wget https://dl.influxdata.com/influxdb/releases/influxdb_1.8.4_amd64.deb && \
sudo dpkg -i influxdb_1.8.4_amd64.deb && \
sudo apt-get update && \
sudo apt-get install -y python3-influxdb && \
rm influxdb_1.8.4_amd64.deb && \
wget https://dl.influxdata.com/telegraf/releases/telegraf_1.17.3-1_amd64.deb && \
sudo dpkg -i telegraf_1.17.3-1_amd64.deb && \
rm telegraf_1.17.3-1_amd64.deb && \
sudo mv /etc/telegraf/telegraf.conf /etc/telegraf/telegraf.conf.bup && \
sudo cp telegraf/telegraf.conf /etc/telegraf/ && \
sudo apt-get install -y libfontconfig1 && \
wget https://dl.grafana.com/oss/release/grafana_7.4.3_amd64.deb && \
sudo dpkg -i grafana_7.4.3_amd64.deb && \
rm grafana_7.4.3_amd64.deb && \
sudo apt-get install snort -y
```

Quan surti el popup, la iface que tinguis al pc i 10.0.0.0/16

```
sudo cp snort/snort.conf /etc/snort/ && \
sudo cp snort/Myrules.rules /etc/snort/rules/
```

```
pip3 install ryu && \
pip3 uninstall eventlet && \
pip3 install eventlet==0.30.2
```

### Configs

Copiar el telegraf.conf y ojo amb el /etc/snort/rules/*.rules

### Services

```
sudo apt install hping3 -y && \
sudo systemctl restart influxdb && \
sudo systemctl restart telegraf && \
sudo systemctl restart grafana-server && \
sudo systemctl restart snort
```

### Create snort interface

```
sudo ip link add name s1-snort type dummy && \
sudo ip link set s1-snort up
```

### Execute MiniNet

```
sudo mn -c && \
sudo mn --custom topo/myTopo.py --topo=mytopo
```

## Give internet acces to h1
=======
### Give internet acces to h1
>>>>>>> main
```
sudo mn --custom myTopo.py --topo=mytopo
sudo ifconfig s1 up
sudo ovs-vsctl add-port s1 enp0s3
sudo ifconfig enp0s3 0
sudo dhclient s1 
```
Mininet:
```
xterm h1
ifconfig h1-eth0 0
dhclient h1-eth0 
nano /etc/resolv.conf //change the nameserver to 8.8.8.8
exit
```
```
xterm h2
ifconfig h2-eth0 0
dhclient h2-eth0 
exit
```

### Configure apache server
from outside the mininet
```
sudo apt install apache2
sudo systemctl stop apache2
sudo gedit /etc/apache2/apache2.conf
```
add the following line to the document ServerName 10.0.0.1

from inside the mininet
```
h1 apachectl -k restart
```

### Configure Mininet (set OpenFlow13 protocol and add port to switch s1 for snort)

Crec que s'hauria de fer `sudo ovs-vsctl set Bridge s1 protocols=OpenFlow13` per?? aleshores no funciona lo altre...

```
sudo ovs-vsctl add-port s1 s1-snort && \
sudo ovs-ofctl show s1
```
### Types of RYU applications

* **simple_switch_rest_13.py**: extends switch to updates MAC address table using PUT/POST.
* **Simple Switch Controller**: Controller that defines the URL to receive HTTP request and its corresponding method. Works with simple_switch_rest_13.py.
To run RYU:
```
sudo ryu-manager ryu/ryu/app/simple_switch_rest_13.py
```
To update/get info from switch using rest:
```
curl -X GET http://127.0.0.1:8080/simpleswitch/mactable/0000000000000001
```
* **rest_firewall.py**: enables firewall control of switches through PUT/POST. Thought for 1 switch, what about multiple ones? Check VLAN part for possible solution.
* **simple_monitor_13.py**: it herits from SimpleSwitch13, but implements a monitor that periodically issues requests of the switch to collect statistical counters.
* **simple_monitor_13_telegraf.py**: same as simple monitor but gives info to telegraf.
* **simple_switch_snort.py**: snort sends data to RYU, which has an event handler to display the alertmsg.
* **SFC.py** (custom): RYU app for flow routing.


### Run RYU application


```
sudo ryu-manager ryu/ryu/app/simple_switch_snort.py ryu/ryu/app/rest_firewall.py simple_monitor_13_telegraf.py
```
To initialize firewall rules run:
```
./ryu/set_up_firewall.sh
```
To set up switch rules:
```
curl -X POST -d '{"dpid": 1, "table_id": 0, "priority": 1, "match": {"in_port": 1, "dl_dst": "00:00:00:00:00:02"}, "actions": [{"type":"OUTPUT", "port": 2}, {"type": "OUTPUT", "port": 4}]}' http://localhost:8080/stats/flowentry/add
```

### Run SNORT

```
sudo snort -i s1-snort -A unsock -l /tmp -c /etc/snort/snort.conf
```

### Influx

```
influx
show databases
use RYU
show measurements
select * from test_measurement where time > now() - 60m
```

### Attack

```
h1 python3 attacks/dos.py h2
```
```
h1 python3 attacks/profe/dos.py h2
```
