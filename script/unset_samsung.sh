#!/bin/bash

base_device="/dev/nvme1n1"

for i in {1..5}
do
    sudo dmsetup remove linear_${i}
done

sudo dmsetup ls

