#!/bin/bash

export RTE_TARGET=x86_64-native-linuxapp-gcc
export RTE_SDK=/usr/src/dpdk-2.0.0

make
