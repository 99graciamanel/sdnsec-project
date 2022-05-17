#!/bin/bash

sudo kill -9 $(ps aux | grep 'wireshark' | awk '{print $2}')

sudo wireshark &
sudo wireshark &
sudo wireshark &
sudo wireshark &
