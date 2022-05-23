#!/bin/bash

ping -f -c 15000 $1
sleep $2
ping -f -c 15000 $1