# sdnsec-project

Copiar el telegraf.conf

```
sudo mn -c
sudo mn --topo single,3 --mac --controller remote --switch ovsk
```

```
sudo ovs-vsctl set Bridge s1 protocols=OpenFlow13
sudo ryu-manager ryu/ryu/app/simple_monitor_13.py packetGenerator.py
```

sudo systemctl restart influxdb
sudo systemctl restart telegraf
sudo systemctl restart grafana-server

