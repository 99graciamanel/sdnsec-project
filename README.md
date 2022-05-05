# SDNSec Project

Copiar el telegraf.conf y ojo amb el /etc/snort/rules/*.rules

```
sudo systemctl restart influxdb
```
```
sudo systemctl restart telegraf
```
```
sudo systemctl restart grafana-server
```
```
sudo systemctl restart snort
```
```
sudo ip link add name s1-snort type dummy
```
```
sudo ip link set s1-snort up
```

```
sudo mn -c
```
```
sudo mn --topo single,3 --mac --controller remote --switch ovsk
```

```
sudo ovs-vsctl set Bridge s1 protocols=OpenFlow13
```
```
sudo ryu-manager ryu/ryu/app/rest_firewall.py simple_monitor_13_telegraf.py
```

```
influx
show databases
use RYU
show measurements
select * from test_measurement where time > now() - 60m
```
