#!/bin/bash

mkdir -p /tmp/snort_s2 && \
sudo snort -i s2-snort -A unsock -l /tmp/snort_s2 -c /etc/snort/snort_s2.conf
