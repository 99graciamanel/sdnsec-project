#!/bin/bash

echo "sudo snort -i s1-snort -A unsock -l /tmp -c /etc/snort/snort_s1.conf"

sudo snort -i s1-snort -A unsock -l /tmp -c /etc/snort/snort_s1.conf
