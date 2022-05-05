# SDNSec Project

Copiar el telegraf.conf

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
sudo systemctl restart influxdb
```
```
sudo systemctl restart telegraf
```
```
sudo systemctl restart grafana-server
```

```
influx
show databases
use RYU
show measurements
select * from test_measurement where time > now() - 60m
```
