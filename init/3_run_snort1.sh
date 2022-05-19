#!/bin/bash

mkdir -p /tmp/snort_s1 && \
sudo snort -i s1-snort -A unsock -l /tmp/snort_s1 -c /etc/snort/snort_s2.conf
