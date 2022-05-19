#!/bin/bash

curl -X PUT http://localhost:8080/firewall/module/enable/0000000000000001
echo
curl http://localhost:8080/firewall/module/status
echo
# If we want to enable pings
#curl -X POST -d '{"nw_src": "10.0.0.1/32", "nw_dst": "10.0.0.2/32", "nw_proto": "ICMP"}' http://localhost:8080/firewall/rules/0000000000000001
# Enable ALL IPv4 traffic
curl -X POST -d '{"nw_src": "10.0.0.1/32", "nw_dst": "10.0.0.3/32"}' http://localhost:8080/firewall/rules/0000000000000001
echo
curl -X POST -d '{"nw_src": "10.0.0.1/32", "nw_dst": "10.0.0.2/32"}' http://localhost:8080/firewall/rules/0000000000000001
echo
curl -X POST -d '{"nw_src": "10.0.0.2/32", "nw_dst": "10.0.0.1/32"}' http://localhost:8080/firewall/rules/0000000000000001
echo
curl -X POST -d '{"nw_src": "10.0.0.2/32", "nw_dst": "10.0.0.3/32"}' http://localhost:8080/firewall/rules/0000000000000001
echo
curl -X POST -d '{"nw_src": "10.0.0.3/32", "nw_dst": "10.0.0.1/32"}' http://localhost:8080/firewall/rules/0000000000000001
echo
curl -X POST -d '{"nw_src": "10.0.0.3/32", "nw_dst": "10.0.0.2/32"}' http://localhost:8080/firewall/rules/0000000000000001
echo

# curl -X POST -d '{"nw_src": "10.0.0.1/32", "nw_dst": "10.0.0.2/32", "nw_proto": "ICMP", "actions":"DENY", "priority": "10"}' http://localhost:8080/firewall/rules/0000000000000001