#!/bin/bash

cd zraid/
./init_zraid.sh sam
cd -

#gap=805306368 #4096 zones
gap=1572864000 #8000 zones

base_device="/dev/nvme1n1"

for i in {1..5}
do
    start_sector=$(( (i - 1) * gap ))

    echo "sudo dmsetup create linear_${i} --table "0 ${gap} linear ${base_device} ${start_sector}""
    sudo dmsetup create linear_${i} --table "0 ${gap} linear ${base_device} ${start_sector}"
done

sudo dmsetup ls

