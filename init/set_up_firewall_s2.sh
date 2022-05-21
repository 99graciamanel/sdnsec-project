#!/bin/bash

curl -X PUT http://localhost:8080/firewall/module/enable/0000000000000002
echo
curl http://localhost:8080/firewall/module/status
echo
# Enable ALL IPv4 traffic
# For h_dmz
curl -X POST -d '{"nw_src": "10.0.0.1/32", "nw_dst": "10.0.0.2/32"}' http://localhost:8080/firewall/rules/0000000000000002
echo
curl -X POST -d '{"nw_src": "10.0.0.1/32", "nw_dst": "10.0.0.3/32"}' http://localhost:8080/firewall/rules/0000000000000002
echo
curl -X POST -d '{"nw_src": "10.0.0.1/32", "nw_dst": "10.0.0.4/32"}' http://localhost:8080/firewall/rules/0000000000000002
echo
curl -X POST -d '{"nw_src": "10.0.0.1/32", "nw_dst": "10.0.0.5/32"}' http://localhost:8080/firewall/rules/0000000000000002
echo
# For h_hp
curl -X POST -d '{"nw_src": "10.0.0.2/32", "nw_dst": "10.0.0.1/32"}' http://localhost:8080/firewall/rules/0000000000000002
echo
curl -X POST -d '{"nw_src": "10.0.0.2/32", "nw_dst": "10.0.0.3/32"}' http://localhost:8080/firewall/rules/0000000000000002
echo
curl -X POST -d '{"nw_src": "10.0.0.2/32", "nw_dst": "10.0.0.4/32"}' http://localhost:8080/firewall/rules/0000000000000002
echo
curl -X POST -d '{"nw_src": "10.0.0.2/32", "nw_dst": "10.0.0.5/32"}' http://localhost:8080/firewall/rules/0000000000000002
echo
# For h_inet
curl -X POST -d '{"nw_src": "10.0.0.3/32", "nw_dst": "10.0.0.1/32"}' http://localhost:8080/firewall/rules/0000000000000002
echo
curl -X POST -d '{"nw_src": "10.0.0.3/32", "nw_dst": "10.0.0.2/32"}' http://localhost:8080/firewall/rules/0000000000000002
echo
curl -X POST -d '{"nw_src": "10.0.0.3/32", "nw_dst": "10.0.0.4/32"}' http://localhost:8080/firewall/rules/0000000000000002
echo
curl -X POST -d '{"nw_src": "10.0.0.3/32", "nw_dst": "10.0.0.5/32"}' http://localhost:8080/firewall/rules/0000000000000002
echo
# For h_lan
curl -X POST -d '{"nw_src": "10.0.0.4/32", "nw_dst": "10.0.0.1/32"}' http://localhost:8080/firewall/rules/0000000000000002
echo
curl -X POST -d '{"nw_src": "10.0.0.4/32", "nw_dst": "10.0.0.2/32"}' http://localhost:8080/firewall/rules/0000000000000002
echo
curl -X POST -d '{"nw_src": "10.0.0.4/32", "nw_dst": "10.0.0.3/32"}' http://localhost:8080/firewall/rules/0000000000000002
echo
curl -X POST -d '{"nw_src": "10.0.0.4/32", "nw_dst": "10.0.0.5/32"}' http://localhost:8080/firewall/rules/0000000000000002
echo
# For h_lan2
curl -X POST -d '{"nw_src": "10.0.0.5/32", "nw_dst": "10.0.0.1/32"}' http://localhost:8080/firewall/rules/0000000000000002
echo
curl -X POST -d '{"nw_src": "10.0.0.5/32", "nw_dst": "10.0.0.2/32"}' http://localhost:8080/firewall/rules/0000000000000002
echo
curl -X POST -d '{"nw_src": "10.0.0.5/32", "nw_dst": "10.0.0.3/32"}' http://localhost:8080/firewall/rules/0000000000000002
echo
curl -X POST -d '{"nw_src": "10.0.0.5/32", "nw_dst": "10.0.0.4/32"}' http://localhost:8080/firewall/rules/0000000000000002
echo

curl http://localhost:8080/firewall/rules/0000000000000002