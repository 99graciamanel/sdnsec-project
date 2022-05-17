sudo ovs-vsctl add-port s1 s1-snort
sudo ovs-ofctl show s1
sudo snort -i s1-snort -A unsock -l /tmp -c /etc/snort/snort.conf