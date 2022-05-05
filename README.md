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
sudo ovs-vsctl add-port s1 s1-snort
sudo ovs-ofctl show s1
sudo snort -i s1-snort -A unsock -l /tmp -c /etc/snort/snort.conf
```

```
sudo ovs-vsctl set Bridge s1 protocols=OpenFlow13
```

sudo ryu-manager ryu/ryu/app/rest_firewall.py ryu/ryu/app/simple_switch_snort.py simple_monitor_13_telegraf.py

He tret el ryu/ryu/app/rest_firewall.py perquè si no no es poden fer proves ??¿?¿¿?¿?¿

```
sudo ryu-manager ryu/ryu/app/simple_switch_snort.py simple_monitor_13_telegraf.py
```

```
influx
show databases
use RYU
show measurements
select * from test_measurement where time > now() - 60m
```
