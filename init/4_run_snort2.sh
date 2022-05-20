#!/bin/bash

echo "sudo snort -i s2-snort -A unsock -l /tmp -c /etc/snort/snort_s2.conf"

sudo snort -i s2-snort -A unsock -l /tmp -c /etc/snort/snort_s2.conf
