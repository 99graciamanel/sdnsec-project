# SDNSec Project

## Installation

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
rm grafana_7.4.3_amd64.deb
```

```
pip3 install ryu && \
pip3 uninstall eventlet && \
pip3 install eventlet==0.30.2
```

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
## Types of RYU applications
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
* **rest_firewall.py**: enables firewall control of switches through PUT/POST.
* **simple_monitor_13.py**:
* **simple_monitor_13_telegraf.py**:
* **simple_switch_snort.py**:
* **SFC.py** (custom):


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
