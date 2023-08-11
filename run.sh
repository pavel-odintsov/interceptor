#!/bin/bash

ulimit -c unlimited
# Blacklist 1GE NIC's
./build/interceptor -l 0-3 -n 3 --pci-blacklist 0000:02:00.0 --pci-blacklist 0000:02:00.1 --pci-blacklist 0000:02:00.2 --pci-blacklist 0000:02:00.3 


