#!/bin/bash

sudo kill -9 $(ps aux | grep 'snort' | awk '{print $2}') && sudo systemctl restart snort.service