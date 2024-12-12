if [ $# -eq 0 ]; then
    echo "Select device: wd or sam"
    exit 1 
fi

sudo umount /dev/mapper/zraid0
sudo umount /dev/nvme3n1p1
sudo dmsetup remove /dev/mapper/zraid0
sudo rmmod zraid
sudo rmmod raizn
sudo rmmod raizn_orig

sleep 1
./reset.sh $1
sleep 1

scheduler="none"
if [ "$1" == "wd" ]; then
    model_name="WZS4C8T1TDSP303" #ZN540
    namespace_suffix="n2"

    device_list=$(lsblk -o NAME,MODEL -d -n | grep "$model_name" | awk '$1 ~ /nvme/ && $1 !~ /1$/ {print "/dev/" $1}' | sort)

    device_string=$(echo $device_list | tr '\n' ' ')

    for i in {0..6}; do
        echo $scheduler | sudo tee /sys/block/nvme${i}n2/queue/scheduler
    done
else
    echo $scheduler | sudo tee /sys/block/nvme1n1/queue/scheduler
fi


cd ../src/
make clean
if [ "$1" == "sam" ]; then
    make CFLAGS="-DPP_INPLACE -DSAMSUNG_MODE"
else
    echo "CFLAGS="-DPP_INPLACE $2""
    make CFLAGS="-DPP_INPLACE $2"
fi
sudo insmod zraid.ko
if [ "$1" == "wd" ]; then
    echo "0 15082717184 zraid 64 16 1 0 $device_string" | sudo dmsetup create zraid0
fi
if [ "$1" == "sam" ]; then
    echo "0 6056574976 zraid 64 16 1 0 /dev/mapper/linear_1 /dev/mapper/linear_2 /dev/mapper/linear_3 /dev/mapper/linear_4 /dev/mapper/linear_5" | sudo dmsetup create zraid0
fi

